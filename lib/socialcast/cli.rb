require 'rubygems'

require "thor"
require 'json'
require 'rest_client'
require 'highline'
require 'net/ldap'
require 'socialcast'
require 'socialcast/message'
require File.join(File.dirname(__FILE__), 'net_ldap_ext')

require 'zlib'
require 'logger'
require 'builder'
require 'set'
require 'fileutils'

# uncomment to debug HTTP traffic
# class ActiveResource::Connection
#   def configure_http(http)
#     http = apply_ssl_options(http)
#     # Net::HTTP timeouts default to 60 seconds.
#     if @timeout
#       http.open_timeout = @timeout
#       http.read_timeout = @timeout
#     end
#     http.set_debug_output STDOUT
#     http
#   end
# end

module Socialcast
  class CLI < Thor
    include Thor::Actions

    method_option :trace, :type => :boolean, :aliases => '-v'
    def initialize(*args); super(*args) end

    desc "authenticate", "Authenticate using your Socialcast credentials"
    method_option :user, :type => :string, :aliases => '-u', :desc => 'email address for the authenticated user'
    method_option :password, :type => :string, :aliases => '-p', :desc => 'password for the authenticated user'
    method_option :domain, :type => :string, :default => 'api.socialcast.com', :desc => 'Socialcast community domain'
    method_option :proxy, :type => :string, :desc => 'HTTP proxy options for connecting to Socialcast server'
    def authenticate
      user = options[:user] || ask('Socialcast username: ')
      password = options[:password] || HighLine.new.ask("Socialcast password: ") { |q| q.echo = false }.to_s
      domain = options[:domain]

      url = ['https://', domain, '/api/authentication'].join
      say "Authenticating #{user} to #{url}"
      params = {:email => user, :password => password }
      RestClient.log = Logger.new(STDOUT) if options[:trace]
      RestClient.proxy = options[:proxy] if options[:proxy]
      resource = RestClient::Resource.new url
      response = resource.post params, :accept => :json
      say "API response: #{response.body.to_s}" if options[:trace]
      communities = JSON.parse(response.body.to_s)['communities']
      domain = communities.detect {|c| c['domain'] == domain} ? domain : communities.first['domain']

      Socialcast.credentials = {:user => user, :password => password, :domain => domain, :proxy => options[:proxy]}
      say "Authentication successful for #{domain}"
    end

    desc "share MESSAGE", "Posts a new message into socialcast"
    method_option :url, :type => :string, :desc => '(optional) url to associate to the message'
    method_option :message_type, :type => :string, :desc => '(optional) force an alternate message_type'
    method_option :attachments, :type => :array, :default => []
    method_option :group_id, :type => :numeric, :desc => "(optional) ID of group to post into"
    def share(message = nil)
      message ||= $stdin.read_nonblock(100_000) rescue nil

      attachment_ids = []
      options[:attachments].each do |path|
        Dir[File.expand_path(path)].each do |attachment|
          say "Uploading attachment #{attachment}..."
          uploader = Socialcast.resource_for_path '/api/attachments', {}, options[:trace]
          uploader.post({:attachment => File.new(attachment)}, {:accept => :json}) do |response, request, result|
            if response.code == 201
              attachment_ids << JSON.parse(response.body)['attachment']['id']
            else
              say "Error uploading attachment: #{response.body}"
            end
          end
        end
      end

      ActiveResource::Base.logger = Logger.new(STDOUT) if options[:trace]
      Socialcast::Message.configure_from_credentials
      Socialcast::Message.create :body => message, :url => options[:url], :message_type => options[:message_type], :attachment_ids => attachment_ids, :group_id => options[:group_id]

      say "Message has been shared"
    end

    desc 'provision', 'provision users from ldap compatible user repository'
    method_option :config, :default => 'ldap.yml', :aliases => '-c'
    method_option :output, :default => 'users.xml.gz', :aliases => '-o'
    method_option :setup, :type => :boolean
    method_option :delete_users_file, :type => :boolean
    method_option :test, :type => :boolean
    method_option :skip_emails, :type => :boolean
    method_option :force, :type => :boolean, :aliases => '-f', :default => false
    method_option :sanity_check, :type => :boolean, :default => false
    method_option :plugins, :type => :array, :desc => "Pass in an array of plugins. Can be either the gem require or the absolute path to a ruby file."
    def provision
      load_plugins options
      config = ldap_config options

      http_config = config.fetch 'http', {}
      mappings = config.fetch 'mappings', {}
      permission_mappings = config.fetch 'permission_mappings', {}

      membership_attribute = permission_mappings.fetch 'attribute_name', 'memberof'
      attributes = mappings.values.map do |mapping_value|
        mapping_value = begin
          mapping_value.camelize.constantize
        rescue NameError
          mapping_value
        end
        case mapping_value
        when Hash
          dup_mapping_value = mapping_value.dup
          dup_mapping_value.delete("value")
          dup_mapping_value.values
        when String
          mapping_value
        when Class, Module
          fail "Please add the attributes method to #{mapping_value}" unless mapping_value.respond_to?(:attributes)
          mapping_value.attributes
        end
      end.flatten
      attributes << membership_attribute

      user_identifier_list = %w{email unique_identifier employee_number}
      user_whitelist = Set.new
      count = 0
      output_file = File.join Dir.pwd, options[:output]

      Zlib::GzipWriter.open(output_file) do |gz|
        xml = Builder::XmlMarkup.new(:target => gz, :indent => 1)
        xml.instruct!
        xml.export do |export|
          export.users(:type => "array") do |users|
            ldap_connections(config) do |key, connection, ldap|
              ldap.search(:return_result => false, :filter => connection["filter"], :base => connection["basedn"], :attributes => attributes) do |entry|
                next if entry.grab(mappings["email"]).blank? || (mappings.has_key?("unique_identifier") && entry.grab(mappings["unique_identifier"]).blank?)

                users.user do |user|
                  entry.build_xml_from_mappings user, ldap, mappings, permission_mappings
                end
                user_whitelist << user_identifier_list.map { |identifier| entry.grab(mappings[identifier]) }
                count += 1
                say "Scanned #{count} users" if ((count % 100) == 0)
              end # search
            end # connections
          end # users
        end # export
      end # gzip
      say "Finished scanning #{count} users"

      if options[:sanity_check]
        say "Sanity checking users currently marked as needing to be terminated"
        ldap_connections(config) do |key, connection, ldap|
          (current_socialcast_users(http_config) - user_whitelist).each do |user_identifiers|
            combined_filters = []
            user_identifier_list.each_with_index do |identifier, index|
              combined_filters << ((mappings[identifier].blank? || user_identifiers[index].nil?) ? nil : Net::LDAP::Filter.eq(mappings[identifier], user_identifiers[index]))
            end
            combined_filters.compact!
            filter = ((combined_filters.size > 1) ? '(|%s)' : '%s') % combined_filters.join(' ')
            filter = Net::LDAP::Filter.construct(filter) & Net::LDAP::Filter.construct(connection["filter"])
            ldap_result = ldap.search(:return_result => true, :base => connection["basedn"], :filter => filter, :attributes => attributes)
            abort("Found user marked for termination that should not be terminated: #{user_identifiers}") unless ldap_result.blank?
          end
        end
      end

      if count == 0 && !options[:force]
        Kernel.abort("Skipping upload to Socialcast since no users were found")
      else
        say "Uploading dataset to Socialcast..."
        resource = Socialcast.resource_for_path '/api/users/provision', http_config
        begin
          File.open(output_file, 'r') do |file|
            request_params = {:file => file}
            request_params[:skip_emails] = 'true' if (config['options']["skip_emails"] || options[:skip_emails])
            request_params[:test] = 'true' if (config['options']["test"] || options[:test])
            resource.post request_params, :accept => :json
          end
        rescue RestClient::Unauthorized => e
          Kernel.abort "Authenticated user either does not have administration privileges or the community is not configured to allow provisioning. Please contact Socialcast support to if you need help." if e.http_code == 401
        end
        say "Finished"
      end
      File.delete(output_file) if (config['options']['delete_users_file'] || options[:delete_users_file])
    end

    no_tasks do
      def load_plugins(options)
        Array.wrap(options[:plugins]).each do |plugin|
          begin
            require plugin
          rescue LoadError => e
            fail "Unable to load #{plugin}: #{e}"
          end
        end
      end

      def ldap_config(options)
        config_file = File.expand_path options[:config]

        if options[:setup]
          create_file config_file do
            File.read File.join(File.dirname(__FILE__), '..', '..', 'config', 'ldap.yml')
          end
          say "Created config file: #{config_file}"
          Kernel.exit 0
        end

        fail "Unable to load configuration file: #{config_file}" unless File.exists?(config_file)
        say "Using configuration file: #{config_file}"
        config = YAML.load_file config_file

        mappings = config.fetch 'mappings', {}
        required_mappings = %w{email first_name last_name}
        required_mappings.each do |field|
          unless mappings.has_key? field
            fail "Missing required mapping: #{field}"
          end
        end

        config
      end

      def ldap_connections(config)
        config["connections"].each_pair do |key, connection|
          say "Connecting to #{key} at #{[connection["host"], connection["port"]].join(':')}"
          ldap = create_ldap_instance(connection)
          say "Searching base DN: #{connection["basedn"]} with filter: #{connection["filter"]}"
          yield key, connection, ldap
        end
      end

      def create_ldap_instance(connection)
        ldap = Net::LDAP.new :host => connection["host"], :port => connection["port"], :base => connection["basedn"]
        ldap.encryption connection['encryption'].to_sym if connection['encryption']
        ldap.auth connection["username"], connection["password"]
        ldap
      end

      def current_socialcast_users(http_config)
        current_socialcast_list = Set.new
        request_params = {:per_page => 500}
        request_params[:page] = 1
        resource = create_socialcast_user_index_request(http_config, request_params)
        while true
          response = resource.get :accept => :json
          result = JSON.parse(response)
          users = result["users"]
          break if users.blank?
          request_params[:page] += 1
          resource = create_socialcast_user_index_request(http_config, request_params)
          users.each do |user|
            current_socialcast_list << [user['contact_info']['email'], user['company_login'], user['employee_number']]
          end
        end
        current_socialcast_list
      end

      def create_socialcast_user_index_request(http_config, request_params)
        path_template = "/api/users?per_page=%{per_page}&page=%{page}"
        Socialcast.resource_for_path((path_template % request_params), http_config)
      end
    end
  end
end
