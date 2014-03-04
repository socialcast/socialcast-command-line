# encoding: UTF-8

require 'rubygems'

require "thor"
require 'json'
require 'rest_client'
require 'highline'
require 'net/ldap'
require 'socialcast'
require 'socialcast/message'
require 'socialcast/provision'
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
    method_option :config, :default => 'ldap.yml', :aliases => '-c', :desc => 'Path to ldap config file'
    method_option :output, :default => Socialcast::Provision::OUTPUT_FILE_NAME, :aliases => '-o', :desc => 'Name of the output file'
    method_option :setup, :type => :boolean, :desc => 'Create an example ldap config file and exit'
    method_option :delete_users_file, :type => :boolean, :desc => 'Delete the output file'
    method_option :test, :type => :boolean, :desc => 'Do not persist changes'
    method_option :skip_emails, :type => :boolean, :desc => 'Do not send signup emails to users'
    method_option :force, :type => :boolean, :aliases => '-f', :default => false, :desc => 'Proceed with provisioning even if no users are found, which would deactivate all users in the community'
    method_option :sanity_check, :type => :boolean, :default => false, :desc => 'Double check that users marked for termination really no longer exist'
    method_option :plugins, :type => :array, :desc => "Pass in an array of plugins. Can be either the gem require or the absolute path to a ruby file"
    def provision
      config = ldap_config options
      load_plugins options

      Socialcast::Provision.provision config, options
    end

    desc 'sync_photos', 'Upload default avatar photos from LDAP repository'
    method_option :config, :default => 'ldap.yml', :aliases => '-c'
    def sync_photos
      config = ldap_config options

      Socialcast::Provision.sync_photos(config)
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

    end
  end
end
