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

      def self.current_user
        @current_user ||= find_current_user
      end

      def self.find_current_user
        response = Socialcast::CommandLine.resource_for_path('/api/userinfo.json').get
        json_body = JSON.parse(response.body)
        if json_body['user']
          json_body['user']
        else
          raise "Unable to find the current user: #{response.body}"
        end
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
