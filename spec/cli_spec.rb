require 'spec_helper'

describe Socialcast::CLI do
  before do
    RSpec::Mocks::setup(self)
  end
  describe '#provision' do
    context 'with test ldap.yml config' do
      @entry = Net::LDAP::Entry.new("dc=example,dc=com")
      @entry[:email] = 'ryan@example.com'
      Net::LDAP.any_instance.stub(:search).and_yield(@entry)

      RestClient::Resource.any_instance.stub(:post)

      Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
    end
    it 'should do stuff'
  end
end
