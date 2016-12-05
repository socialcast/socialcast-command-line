# encoding: UTF-8

require 'rubygems'

require "thor"
require 'json'
require 'rest_client'
require 'highline'

require 'logger'
require 'fileutils'

module Socialcast
  module CommandLine
    class CLI < Thor
      include Thor::Actions

      method_option :trace, :type => :boolean, :aliases => '-t'
      def initialize(*args); super; end

      desc "info", "Information about the socialcast command"
      method_option :version, :type => :string, :aliases => '-v', :description => 'print the version number and exit'
      def info
        if options["version"]
          say "Socialcast Command Line #{Socialcast::CommandLine::VERSION}"
        end
      end
      default_task :info

      desc "authenticate", "Authenticate using your Socialcast credentials"
      method_option :user, :type => :string, :aliases => '-u', :desc => 'email address for the authenticated user'
      method_option :password, :type => :string, :aliases => '-p', :desc => 'password for the authenticated user'
      method_option :domain, :type => :string, :default => 'api.socialcast.com', :desc => 'Socialcast community domain'
      method_option :proxy, :type => :string, :desc => 'HTTP proxy options for connecting to Socialcast server'
      def authenticate
        user = options[:user] || ask('Socialcast login (email address): ')
        password = options[:password] || HighLine.new.ask("Socialcast password: ") { |q| q.echo = false }.to_s

        params = { :email => user, :password => password }
        response = Socialcast::CommandLine::Authenticate.new(:user, options, params).request
        communities = JSON.parse(response.body.to_s)['communities']
        domain = communities.detect { |c| c['domain'] == options[:domain] } ? options[:domain] : communities.first['domain']

        Socialcast::CommandLine.credentials = {
          :user => user,
          :password => password,
          :domain => domain
        }
        say "Authentication successful for #{domain}"
      end

      desc "authenticate_external_system", "Authenticate using an external system"
      method_option :api_client_identifier, :type => :string, :aliases => '-i', :desc => 'the identifier of the external system'
      method_option :api_client_secret, :type => :string, :aliases => '-s', :desc => 'the secret key of the external system'
      method_option :proxy, :type => :string, :desc => 'HTTP proxy options for connecting to Socialcast server'
      method_option :domain, :type => :string, :default => 'api.socialcast.com', :desc => 'Socialcast community domain'
      def authenticate_external_system
        api_client_identifier = options[:api_client_identifier] || ask("Socialcast external system identifier: ")
        api_client_secret = options[:api_client_secret] || ask("Socialcast external system API secret: ")

        headers = {
          :headers => {
            :Authorization => "SocialcastApiClient #{api_client_identifier}:#{api_client_secret}"
          }
        }

        Socialcast::CommandLine::Authenticate.new(:external_system, options, {}, headers).request

        Socialcast::CommandLine.credentials = {
          :api_client_identifier => api_client_identifier,
          :api_client_secret => api_client_secret,
        }
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
            uploader = Socialcast::CommandLine.resource_for_path '/api/attachments', {}, options[:trace]
            uploader.post({:attachment => File.new(attachment)}, {:accept => :json}) do |response, request, result|
              if response.code == 201
                attachment_ids << JSON.parse(response.body)['attachment']['id']
              else
                say "Error uploading attachment: #{response.body}"
              end
            end
          end
        end

        Socialcast::CommandLine::Message.with_debug options[:trace] do
          Socialcast::CommandLine::Message.create :body => message, :url => options[:url], :message_type => options[:message_type], :attachment_ids => attachment_ids, :group_id => options[:group_id]
        end
        say "Message has been shared"
      end

      desc 'provision', 'provision users from ldap compatible user repository'
      method_option :config, :default => 'ldap.yml', :aliases => '-c', :desc => 'Path to ldap config file'
      method_option :output, :default => Socialcast::CommandLine::ProvisionUser::DEFAULT_OUTPUT_FILE, :aliases => '-o', :desc => 'Name of the output file'
      method_option :setup, :type => :boolean, :desc => 'Create an example ldap config file and exit'
      method_option :delete_users_file, :type => :boolean, :desc => 'Delete the output file'
      method_option :test, :type => :boolean, :desc => 'Do not persist changes'
      method_option :skip_emails, :type => :boolean, :default => false, :desc => 'Do not send signup emails to users'
      method_option :add_only, :type => :boolean, :default => false, :desc => 'Only add users'
      method_option :force, :type => :boolean, :aliases => '-f', :default => false, :desc => 'Proceed with provisioning even if no users are found, which would deactivate all users in the community'
      method_option :plugins, :type => :array, :desc => "Pass in an array of plugins. Can be either the gem require or the absolute path to a ruby file"
      method_option :external_system, :type => :boolean, :desc => "Use an external system for authentication purposes"
      def provision
        config = ldap_config options
        load_plugins options

        Socialcast::CommandLine::ProvisionUser.new(config, options).provision

      rescue Socialcast::CommandLine::ProvisionUser::ProvisionError => e
        Kernel.abort e.message
      end

      desc 'sync_photos', 'Upload default avatar photos from LDAP repository'
      method_option :config, :default => 'ldap.yml', :aliases => '-c'
      method_option :force_sync, :type => :boolean, :aliases => '-f', :desc => 'Pushes all photos from LDAP to socialcast'
      def sync_photos
        config = ldap_config options

        Socialcast::CommandLine::ProvisionPhoto.new(config, options).sync
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
              File.read File.join(File.dirname(__FILE__), '..', '..', '..', 'config', 'ldap.yml')
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
end
