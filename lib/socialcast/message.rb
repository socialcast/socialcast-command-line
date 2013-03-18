require 'active_resource'

module Socialcast
  class Message < ActiveResource::Base
    headers['Accept'] = 'application/json'

    def self.configure_from_credentials
      Socialcast::Message.site = ['https://', Socialcast.credentials[:domain], '/api'].join
      Socialcast::Message.proxy = Socialcast.credentials[:proxy] if Socialcast.credentials[:proxy]
      Socialcast::Message.user = Socialcast.credentials[:user]
      Socialcast::Message.password = Socialcast.credentials[:password]
    end
  end
end

