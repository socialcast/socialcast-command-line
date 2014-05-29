module Socialcast
  module CommandLine
    class Authenticate
      attr_accessor :authenticate_type, :options, :params, :headers

      def initialize(authenticate_type, options, params, headers = {})
        self.authenticate_type = authenticate_type
        self.options = options
        self.params = params
        self.headers = headers
      end

      def request
        @request ||= send_request
      end

      private

      def send_request
        puts "Authenticating to #{url}"
        RestClient.log = Logger.new($stdout) if options[:trace]
        RestClient.proxy = options[:proxy] if options[:proxy]
        resource = RestClient::Resource.new url, headers
        response = resource.post params, :accept => :json
        puts "API response: #{response.body.to_s}" if options[:trace]
        set_default_credentials
        response
      end

      def set_default_credentials
        Socialcast::CommandLine.credentials = {
          :domain => domain,
          :proxy => options[:proxy]
        }
      end

      def url
        @url ||= File.join("https://", domain, 'api', (authenticate_type == :external_system ? 'external_systems/' : ''), 'authentication')
      end

      def domain
        options[:domain]
      end
    end
  end
end
