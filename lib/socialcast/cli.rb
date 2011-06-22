require "thor"
require 'json'
require 'rest_client'
require 'highline'
require 'socialcast'
require 'socialcast/message'

module Socialcast
  class CLI < Thor
    include Thor::Actions
    include Socialcast
    default_task :share

    desc "authenticate", "Authenticate using your Socialcast credentials"
    method_option :user, :type => :string, :aliases => '-u', :desc => 'email address for the authenticated user'
    method_option :domain, :type => :string, :default => 'api.socialcast.com', :desc => 'socialcast community domain'
    method_option :trace, :type => :boolean, :default => false, :aliases => '-v'
    def authenticate
      user = options[:user] || ask('Socialcast username: ')
      password = HighLine.new.ask("Socialcast password: ") { |q| q.echo = false }
      domain = options[:domain]

      url = ['https://', domain, '/api/authentication.json'].join
      say "Authenticating #{user} to #{url}"
      params = {:email => user, :password => password }
      resource = RestClient::Resource.new url
      response = resource.post params
      puts "API response: #{response.body.to_s}" if options[:trace]
      communities = JSON.parse(response.body.to_s)['communities']
      domain = communities.detect {|c| c['domain'] == domain} ? domain : communities.first['domain']

      save_credentials :user => user, :password => password, :domain => domain
      say "Authentication successful for #{domain}"
    end

    desc "share MESSAGE", "Posts a new message into socialcast"
    method_option :url, :type => :string
    method_option :attachments, :type => :array, :default => []
    def share(message = nil)
      message ||= $stdin.read_nonblock(100_000) rescue nil

      attachment_ids = []
      options[:attachments].each do |path|
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

      Socialcast::Message.create :body => message, :url => options[:url], :attachment_ids => attachment_ids

      say "Message has been shared"
    end
  end
end
