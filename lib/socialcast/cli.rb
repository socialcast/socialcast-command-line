require "thor"
require 'json'
# require 'highline'
require 'rest_client'

require 'socialcast'
require 'socialcast/message'


module Socialcast
  class CLI < Thor
    include Thor::Actions
    include Socialcast
    default_task :share

    desc "share", "Posts a new message into socialcast"
    method_option :message, :type => :string, :aliases => '-m'
    method_option :url, :type => :string
    method_option :attachments, :type => :array, :default => []
    def share
      message ||= $stdin.read_nonblock(100_000) rescue nil

      attachment_ids = []
      options.attachments.each do |path|
        Dir[File.expand_path(path)].each do |attachment|
          attachment_url = ['https://', credentials[:domain], '/api/attachments.json'].join
          say "Uploading attachment #{attachment}..."
          attachment_uploader = RestClient::Resource.new attachment_url, :user => credentials[:user], :password => credentials[:password]
          attachment_uploader.post :attachment => File.new(attachment) do |response, request, result|
            if response.code == 201
              attachment_ids << JSON.parse(response.body)['attachment']['id']
            else
              say "Error uploading attachment: #{response.body}"
            end
          end
        end
      end

      Socialcast::Message.site = ['https://', credentials[:domain], '/api'].join
      Socialcast::Message.user = credentials[:user]
      Socialcast::Message.password = credentials[:password]

      Socialcast::Message.create :body => message, :url => options.url, :attachment_ids => attachment_ids

      say "Message has been shared"
    end
  end
end
