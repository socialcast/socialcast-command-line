require 'rubygems'
require 'bundler/setup'
require 'webmock/rspec'
require 'rspec/mocks'
require 'pry'
RSpec::Mocks::setup(Object.new)

require_relative '../lib/socialcast'

RSpec.configure do |config|
  config.mock_with :rspec

  config.before do
    stubbed_credentials = File.join(File.dirname(__FILE__), '..', 'fixtures')
    Socialcast::CommandLine.stub(:config_dir).and_return(stubbed_credentials)
  end

  def create_entry(cn, entry_attributes)
    Net::LDAP::Entry.new("cn=#{cn},dc=example,dc=com").tap do |e|
      entry_attributes.each_pair do |attr, value|
        e[attr] = value
      end
    end
  end
end
