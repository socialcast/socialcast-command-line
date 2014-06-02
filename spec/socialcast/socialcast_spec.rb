require 'spec_helper'

describe Socialcast::CommandLine do

  let(:custom_file) { File.join(File.dirname(__FILE__), '..', 'fixtures', 'custom_credentials.yml') }
  let(:stubbed_credentials) { File.join(File.dirname(__FILE__), '..', 'fixtures') }
  before { Socialcast::CommandLine.stub(:config_dir).and_return(stubbed_credentials) }
  let!(:orig_credentials) { Socialcast::CommandLine.credentials }

  describe '.credentials_file' do
    subject { Socialcast::CommandLine.credentials_file }
    context 'with ENV variable' do
      before { ENV['SC_CREDENTIALS_FILE'] = custom_file }
      after { ENV['SC_CREDENTIALS_FILE'] = nil }
      it { should == custom_file }
    end
    context 'without ENV variable' do
      it { should == File.join(Socialcast::CommandLine.config_dir, 'credentials.yml') }
    end
  end

  describe '.credentials' do
    subject { Socialcast::CommandLine.credentials }
    describe 'with ENV variable' do
      before { ENV['SC_CREDENTIALS_FILE'] = custom_file }
      after { ENV['SC_CREDENTIALS_FILE'] = nil }
      it { subject[:user].should == 'mike@socialcast.com' }
    end
    describe 'without ENV variable' do
      it { subject[:user].should == 'ryan@socialcast.com' }
    end
  end

  describe '.credentials=' do
    let(:options) { { :user => 'mike@socialcast.com', :password => 'mypassword' } }
    before { Socialcast::CommandLine.credentials = options }
    after { Socialcast::CommandLine.credentials = orig_credentials }
    subject { Socialcast::CommandLine.credentials }
    context 'modifies the credentials file with the options content' do
      it { subject[:user].should == 'mike@socialcast.com' }
    end
    context 'only changes the content provided' do
      let(:options) { { :api_client_secret => 'mysecret', :api_client_identifier => 'my_id' } }
      it { subject[:api_client_identifier].should == 'my_id' }
      it { subject[:user].should == 'ryan@socialcast.com' }
    end
  end

  describe '.resource_for_path' do
    let(:path) { '/mypath' }
    let(:url) { "https://test.staging.socialcast.com#{path}" }
    before do
      RestClient::Resource.should_receive(:new).with(url, options)
      Socialcast::CommandLine.resource_for_path(path, options)
    end
    context 'when using basic auth' do
      let(:options) { { :user => Socialcast::CommandLine.credentials[:user], :password => Socialcast::CommandLine.credentials[:password] } }
      it 'sends user email and password' do end
    end
    context 'when using an external system' do
      let(:options) { { :external_system => true, :headers => { :Authorization=>"SocialcastApiClient my_id:mysecret" } } }
      it 'sends external system credentials' do end
    end
  end
end
