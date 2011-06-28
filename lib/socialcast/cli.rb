require "thor"
require 'json'
require 'rest_client'
require 'highline'
require 'socialcast'
require 'socialcast/message'

require 'zlib'
require 'builder'
require 'net/ldap'

module Socialcast
  class CLI < Thor
    include Thor::Actions
    include Socialcast

    desc "authenticate", "Authenticate using your Socialcast credentials"
    method_option :user, :type => :string, :aliases => '-u', :desc => 'email address for the authenticated user'
    method_option :domain, :type => :string, :default => 'api.socialcast.com', :desc => 'socialcast community domain'
    method_option :trace, :type => :boolean, :default => false, :aliases => '-v'
    def authenticate
      user = options[:user] || ask('Socialcast username: ')
      password = HighLine.new.ask("Socialcast password: ") { |q| q.echo = false }
      domain = options[:domain]

      url = ['https://', domain, '/api/authentication.json'].join
      say "Authenticating #{user} to #{url}"
      params = {:email => user, :password => password }
      resource = RestClient::Resource.new url
      response = resource.post params
      puts "API response: #{response.body.to_s}" if options[:trace]
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
    method_option :setup, :default => false
    method_option :config, :default => 'ldap.yml', :aliases => '-c'
    method_option :output, :default => 'users.xml.gz', :aliases => '-o'
    method_option :delete_users_file, :default => true
    def provision
      config_file = File.join Dir.pwd, options[:config]

      if options[:setup]
        create_file config_file do
          File.read File.join(File.dirname(__FILE__), '..', '..', 'config', 'ldap.yml')
        end
        return
      end

      config = YAML.load_file config_file
      unless config.has_key? "connections"
        config["connections"] = [{
          "ldap_username" => config["ldap_username"],
          "ldap_pwd" => config["ldap_pwd"],
          "ldap_host" => config["ldap_host"],
          "ldap_port" => config["ldap_port"],
          "basedn" => config["basedn"],
          "filter" => config["filter"]
        }]
      end

      required_mappings = %w{email first_name last_name}
      required_mappings.each do |field|
        unless config["mappings"].has_key? field
          fail "Missing required mapping: #{field}"
        end
      end

      logger = Logger.new(STDOUT)
      output_file = File.join Dir.pwd, options[:output]
      Zlib::GzipWriter.open(output_file) do |gz|
        xml = Builder::XmlMarkup.new(:target => gz, :indent => 1)
        xml.instruct!
        xml.export do |export|
          export.users(:type => "array") do |users|
            config["connections"].each do |connection|
              say "Connecting to #{connection["ldap_host"]} #{connection["basedn"]}..."

              ldap = Net::LDAP.new :host => connection["ldap_host"], :port => connection["ldap_port"], :base => connection["basedn"]
              ldap.encryption connection['encryption'].to_sym if connection['encryption']
              ldap.auth connection["ldap_username"], connection["ldap_pwd"]
              say "Connected"
              say "Searching..." 
              count = 0
              ldap.search(:return_result => false, :filter => connection["filter"], :base => connection["basedn"]) do |entry|
                next if grab_value(entry[config["mappings"]["email"]]).blank? || (config["mappings"].has_key?("unique_identifier") && grab_value(entry[config["mappings"]["unique_identifier"]]).blank?)
                users.user do |user|
                  %w{unique_identifier first_name last_name employee_number}.each do |attribute|
                    next unless config['mappings'].has_key?(attribute)
                    user.tag! attribute, grab_value(entry[config["mappings"][attribute]])
                  end
                  user.tag! 'contact-info' do |contact_info|
                    %w{email location cell_phone office_phone}.each do |attribute|
                      next unless config['mappings'].has_key?(attribute)
                      contact_info.tag! attribute, grab_value(entry[config["mappings"][attribute]])
                    end
                  end
                  user.tag! 'custom-fields', :type => "array" do |custom_fields|
                    %w{title}.each do |attribute|
                      next unless config['mappings'].has_key?(attribute)
                      custom_fields.tag! 'custom-field' do |custom_field|
                        custom_field.id(attribute)
                        custom_field.value(grab_value(entry[config["mappings"][attribute]]))
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

      RestClient.log = Logger.new(STDOUT)
      RestClient.proxy = config["http_proxy"] if config["http_proxy"]
      url = ['https://', credentials[:domain], '/api/users/provision'].join
      private_resource = RestClient::Resource.new url, :user => credentials[:username], :password => credentials[:password], :timeout => 660
      File.open(output_file, 'r') do |file|
        request_params = {:file => file}
        request_params[:skip_emails] = "true" if config["skip_emails"]
        request_params[:test] = "true" if config["test"]
        private_resource.post request_params
      end

      File.delete(output_file) if options[:delete_users_file]

      say "Finished"
    end
  end
end
