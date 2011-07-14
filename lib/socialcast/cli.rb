require "thor"
require 'json'
require 'rest_client'
require 'highline'
require 'socialcast'
require 'socialcast/message'
require File.join(File.dirname(__FILE__), 'net_ldap_ext')

require 'zlib'
require 'logger'
require 'builder'
require 'net/ldap'

module Socialcast
  class CLI < Thor
    include Thor::Actions
    include Socialcast

    desc "authenticate", "Authenticate using your Socialcast credentials"
    method_option :user, :type => :string, :aliases => '-u', :desc => 'email address for the authenticated user'
    method_option :domain, :type => :string, :default => 'api.socialcast.com', :desc => 'socialcast community domain'
    method_option :trace, :type => :boolean, :aliases => '-v'
    def authenticate
      user = options[:user] || ask('Socialcast username: ')
      password = HighLine.new.ask("Socialcast password: ") { |q| q.echo = false }
      domain = options[:domain]

      url = ['https://', domain, '/api/authentication.json'].join
      say "Authenticating #{user} to #{url}"
      params = {:email => user, :password => password }
      resource = RestClient::Resource.new url
      RestClient.log = Logger.new(STDOUT) if options[:trace]
      response = resource.post params
      say "API response: #{response.body.to_s}" if options[:trace]
      communities = JSON.parse(response.body.to_s)['communities']
      domain = communities.detect {|c| c['domain'] == domain} ? domain : communities.first['domain']

      save_credentials :user => user, :password => password, :domain => domain
      say "Authentication successful for #{domain}"
    end

    desc "share MESSAGE", "Posts a new message into socialcast"
    method_option :url, :type => :string
    method_option :attachments, :type => :array, :default => []
    def share(message = nil)
      message ||= $stdin.read_nonblock(100_000) rescue nil

      attachment_ids = []
      options[:attachments].each do |path|
        Dir[File.expand_path(path)].each do |attachment|
          attachment_url = ['https://', credentials[:domain], '/api/attachments.json'].join
          say "Uploading attachment #{attachment}..."
          attachment_uploader = RestClient::Resource.new attachment_url, :user => credentials[:user], :password => credentials[:password]
          attachment_uploader.post :attachment => File.new(attachment) do |response, request, result|
            if response.code == 201
              attachment_ids << JSON.parse(response.body)['attachment']['id']
            else
              say "Error uploading attachment: #{response.body}"
            end
          end
        end
      end

      Socialcast::Message.site = ['https://', credentials[:domain], '/api'].join
      Socialcast::Message.user = credentials[:user]
      Socialcast::Message.password = credentials[:password]

      Socialcast::Message.create :body => message, :url => options[:url], :attachment_ids => attachment_ids

      say "Message has been shared"
    end

    desc 'provision', 'provision users from ldap compatible user repository'
    method_option :config, :default => 'ldap.yml', :aliases => '-c'
    method_option :output, :default => 'users.xml.gz', :aliases => '-o'
    method_option :setup, :type => :boolean
    method_option :delete_users_file, :type => :boolean
    method_option :test, :type => :boolean
    method_option :skip_emails, :type => :boolean
    def provision
      config_file = File.join Dir.pwd, options[:config]

      if options[:setup]
        create_file config_file do
          File.read File.join(File.dirname(__FILE__), '..', '..', 'config', 'ldap.yml')
        end
        return
      end

      fail "Unable to load configuration file: #{config_file}" unless File.exist?(config_file)
      say "Using configuration file: #{config_file}"
      config = YAML.load_file config_file
      required_mappings = %w{email first_name last_name}
      mappings = config.fetch 'mappings', {}
      required_mappings.each do |field|
        unless mappings.has_key? field
          fail "Missing required mapping: #{field}"
        end
      end

      permission_mappings = config.fetch 'permission_mappings', {}
      membership_attribute = permission_mappings.fetch 'attribute_name', 'memberof'
      attributes = mappings.values
      attributes << membership_attribute

      output_file = File.join Dir.pwd, options[:output]
      Zlib::GzipWriter.open(output_file) do |gz|
        xml = Builder::XmlMarkup.new(:target => gz, :indent => 1)
        xml.instruct!
        xml.export do |export|
          export.users(:type => "array") do |users|
            config["connections"].each_pair do |key, connection|
              say "Connecting to #{key} at #{[connection["host"], connection["port"]].join(':')} with filter #{connection["basedn"]}"

              ldap = Net::LDAP.new :host => connection["host"], :port => connection["port"], :base => connection["basedn"]
              ldap.encryption connection['encryption'].to_sym if connection['encryption']
              ldap.auth connection["username"], connection["password"]
              say "Connected"
              say "Searching..." 
              count = 0

              ldap.search(:return_result => false, :filter => connection["filter"], :base => connection["basedn"], :attributes => attributes) do |entry|
                next if entry.grab(mappings["email"]).blank? || (mappings.has_key?("unique_identifier") && entry.grab(mappings["unique_identifier"]).blank?)

                users.user do |user|
                  primary_attributes = %w{unique_identifier first_name last_name employee_number}
                  primary_attributes.each do |attribute|
                    next unless mappings.has_key?(attribute)
                    user.tag! attribute, entry.grab(mappings[attribute])
                  end

                  contact_attributes = %w{email location cell_phone office_phone}
                  user.tag! 'contact-info' do |contact_info|
                   contact_attributes.each do |attribute|
                      next unless mappings.has_key?(attribute)
                      contact_info.tag! attribute, entry.grab(mappings[attribute])
                    end
                  end

                  custom_attributes = mappings.keys - (primary_attributes + contact_attributes)
                  user.tag! 'custom-fields', :type => "array" do |custom_fields|
                    custom_attributes.each do |attribute|
                      custom_fields.tag! 'custom-field' do |custom_field|
                        custom_field.id attribute
                        custom_field.label attribute
                        custom_field.value entry.grab(mappings[attribute])
                      end
                    end
                  end

                  memberships = entry[membership_attribute]
                  external_ldap_group = permission_mappings.fetch('account_types', {})['external']
                  if external_ldap_group && memberships.include?(external_ldap_group)
                    user.tag! 'account-type', 'external'
                  else
                    user.tag! 'account-type', 'member'
                    if permission_roles_mappings = permission_mappings['roles']
                      user.tag! 'roles', :type => 'array' do |roles|
                        permission_roles_mappings.each_pair do |socialcast_role, ldap_group|
                          roles.role socialcast_role if entry[membership_attribute].include?(ldap_group)
                        end
                      end
                    end
                  end
                end # user
                count += 1
                say "Scanned #{count} users..." if ((count % 100) == 0)
              end # search
            end # connections
          end # users
        end # export
      end # gzip

      say "Finished Scanning" 
      say "Sending to Socialcast" 

      http_config = config.fetch('http', {})
      RestClient.log = Logger.new(STDOUT)
      RestClient.proxy = http_config['proxy'] if http_config['proxy']
      url = ['https://', credentials[:domain], '/api/users/provision'].join
      private_resource = RestClient::Resource.new url, :user => credentials[:user], :password => credentials[:password], :timeout => http_config['timeout']
      File.open(output_file, 'r') do |file|
        request_params = {:file => file}
        request_params[:skip_emails] = 'true' if (config['options']["skip_emails"] || options[:skip_emails])
        request_params[:test] = 'true' if (config['options']["test"] || options[:test])
        private_resource.post request_params
      end

      File.delete(output_file) if (config['options']['delete_users_file'] || options[:delete_users_file])

      say "Finished"
    end
  end
end
