require 'yaml'
require 'base64'
require 'digest'
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
    OBFUSCATED_CREDENTIAL_KEYS=[:password].to_set

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
      clarify_credential_hash(YAML.load_file(credentials_file))
    end

    def self.credentials=(options)
      obfuscated_credentials = obfuscate_credential_hash(options)

      File.open(credentials_file, "a+") do |f|
        existing_content = YAML.load(f.read) || {}
        f.truncate(0)
        f.write(existing_content.merge(obfuscated_credentials).to_yaml)
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

    private

    SHA1_HEX_LENGTH=40

    def self.obfuscate_credential_hash(credential_hash)
      Hash[ credential_hash.map do |key, value|
        if OBFUSCATED_CREDENTIAL_KEYS.include? key
          encoded_value = Base64.strict_encode64(value)

          # Encoding as UTF-8 needed to prevent YAML from going full-binary w/ these values
          value = ((Digest::SHA1.new << encoded_value).to_s + encoded_value).encode('UTF-8')
        end
        [key, value]
      end]
    end

    def self.clarify_credential_hash(credential_hash)
      Hash[credential_hash.map do |key, value|
        returned_value = value

        if OBFUSCATED_CREDENTIAL_KEYS.include? key
          claimed_checksum = value[0...SHA1_HEX_LENGTH] || ""
          encoded_payload = value[SHA1_HEX_LENGTH..-1] || ""
          observed_checksum = (Digest::SHA1.new << encoded_payload).to_s
          decoded_payload = Base64.strict_decode64(encoded_payload) rescue nil 

          if decoded_payload && claimed_checksum == observed_checksum
            returned_value = decoded_payload
          else
            puts "Warning: #{key} didn't decode successfully. Falling back to the literal value. Try re-running 'socialcast authenticate' if authentication problems occur."
          end
        end

        [key, returned_value]
      end]
    end
  end
end
