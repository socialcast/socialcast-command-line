require 'yaml'
require 'fileutils'
require File.join(File.dirname(__FILE__), 'ext', 'array_ext') unless Array.respond_to?(:wrap)
require File.join(File.dirname(__FILE__), 'ext', 'string_ext')

module Socialcast
  class << self
    def config_dir
      config_dir = File.expand_path '~/.socialcast'
      FileUtils.mkdir config_dir, :mode => 0700 unless File.exist?(config_dir)
      config_dir
    end
    def credentials_file
      File.join config_dir, 'credentials.yml'
    end
    def credentials
      fail 'Unknown Socialcast credentials.  Run `socialcast authenticate` to initialize' unless File.exist?(credentials_file)
      @@credentials ||= YAML.load_file(credentials_file)
    end
    def credentials=(options)
      File.open(credentials_file, "w") do |f|
        f.write(options.to_yaml)
      end
      File.chmod 0600, credentials_file
    end
    def basic_auth_options
      {:user => credentials[:user], :password => credentials[:password]}
    end
    def default_options
      basic_auth_options
    end
    # configure restclient for api call
    def resource_for_path(path, options = {}, debug = true)
      RestClient.log = Logger.new(STDOUT) if debug
      RestClient.proxy = credentials[:proxy] if credentials[:proxy]
      url = ['http://', credentials[:domain], path].join
      RestClient::Resource.new url, options.merge(default_options)
    end
  end
end
