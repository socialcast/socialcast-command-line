module Socialcast
  module CommandLine
    class Message
      class << self
        attr_accessor :debug

        def create(attributes = {})
          options = {
            :user => user,
            :password => password,
          }
          RestClient.proxy = proxy if proxy
          resource = RestClient::Resource.new create_url, options
          attributes_json = { :message => attributes }.to_json
          response = resource.post attributes_json, :accept => :json, :content_type => :json
          puts "API response: #{response.body.to_s}" if debug
          response
        end

        def with_debug(new_value)
          old_value = debug
          self.debug = new_value
          yield
        ensure
          self.debug = old_value
        end

        def site
          File.join('https://', Socialcast::CommandLine.credentials[:domain], 'api')
        end

        def proxy
          Socialcast::CommandLine.credentials[:proxy] if Socialcast::CommandLine.credentials[:proxy]
        end

        def user
          Socialcast::CommandLine.credentials[:user]
        end

        def password
          Socialcast::CommandLine.credentials[:password]
        end

        def create_url
          File.join(site, 'messages.json')
        end
      end
    end
  end
end
