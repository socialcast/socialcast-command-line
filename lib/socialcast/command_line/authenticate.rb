module Socialcast
  module CommandLine
    class Authenticate
      attr_accessor :authenticate_type, :options, :params

      def initialize(authenticate_type, options, params)
        self.authenticate_type = authenticate_type
        self.options = options
        self.params = params
      end

      def request
        @request ||= send_request
      end

      private

      def send_request
        puts "Authenticating to #{url}"
        RestClient.log = Logger.new($stdout) if options[:trace]
        RestClient.proxy = options[:proxy] if options[:proxy]
        resource = RestClient::Resource.new url
        response = resource.post params, :accept => :json
        puts "API response: #{response.body.to_s}" if options[:trace]
        set_basic_credentials
        response
      end

      def set_basic_credentials
        Socialcast::CommandLine.credentials = {
          :domain => domain,
          :proxy => options[:proxy]
        }
      end

      def url
        @url ||= ['https://', domain, '/api/', (authenticate_type == :external_system ? 'external_systems/' : nil), 'authentication'].join
      end

      def domain
        options[:domain]
      end
    end
  end
end
