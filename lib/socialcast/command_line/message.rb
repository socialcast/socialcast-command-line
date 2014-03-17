require 'active_resource'

ActiveResource::Base.include_root_in_json = true

module Socialcast
  module CommandLine
    class Message < ActiveResource::Base
      headers['Accept'] = 'application/json'

      def self.configure_from_credentials
        Socialcast::CommandLine::Message.site = ['https://', Socialcast::CommandLine.credentials[:domain], '/api'].join
        Socialcast::CommandLine::Message.proxy = Socialcast::CommandLine.credentials[:proxy] if Socialcast::CommandLine.credentials[:proxy]
        Socialcast::CommandLine::Message.user = Socialcast::CommandLine.credentials[:user]
        Socialcast::CommandLine::Message.password = Socialcast::CommandLine.credentials[:password]
      end
    end
  end
end
