require 'active_resource'

module Socialcast
  class Message < ActiveResource::Base
    def self.configure_from_credentials
      Socialcast::Message.site = ['https://', Socialcast.credentials[:domain], '/api'].join
      Socialcast::Message.proxy = credentials[:proxy] if Socialcast.credentials[:proxy]
      Socialcast::Message.user = Socialcast.credentials[:user]
      Socialcast::Message.password = Socialcast.credentials[:password]
    end
  end
end

