require 'yaml'
require 'fileutils'

require_relative 'socialcast/command_line/ldap_connector'
require_relative 'socialcast/command_line/provisioner'
require_relative 'socialcast/command_line/authenticate'
require_relative 'socialcast/command_line/provision_user'
require_relative 'socialcast/command_line/provision_photo'
require_relative 'socialcast/command_line/message'
require_relative 'socialcast/command_line/cli'
require_relative 'socialcast/command_line/version'

module Socialcast
  module CommandLine
    def self.config_dir
      config_dir = File.expand_path '~/.socialcast'
      FileUtils.mkdir config_dir, :mode => 0700 unless File.exist?(config_dir)
      config_dir
    end

    def self.credentials_file
      ENV['SC_CREDENTIALS_FILE'] || File.join(config_dir, 'credentials.yml')
    end

    def self.credentials
      fail 'Unknown Socialcast credentials.  Run `socialcast authenticate` to initialize' unless File.exist?(credentials_file)
      YAML.load_file(credentials_file)
    end

    def self.credentials=(options)
      File.open(credentials_file, "a+") do |f|
        existing_content = YAML.load(f.read) || {}
        f.truncate(0)
        f.write(existing_content.merge(options).to_yaml)
      end
      File.chmod 0600, credentials_file
    end

    # configure restclient for api call
    def self.resource_for_path(path, options = {}, debug = true)
      RestClient.log = Logger.new(STDOUT) if debug
      RestClient.proxy = credentials[:proxy] if credentials[:proxy]
      url = ['https://', credentials[:domain], path].join
      RestClient::Resource.new url, options.merge(authentication(options))
    end

    def self.authentication(options)
      if options[:external_system]
        { :headers => { :Authorization => "SocialcastApiClient #{credentials[:api_client_identifier]}:#{credentials[:api_client_secret]}" } }
      else
        { :user => credentials[:user], :password => credentials[:password] }
      end
    end

  end
end
