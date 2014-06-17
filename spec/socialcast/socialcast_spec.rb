require 'spec_helper'

describe Socialcast::CommandLine do
  let(:custom_file) { File.join(File.dirname(__FILE__), '..', 'fixtures', 'custom_credentials.yml') }
  let(:stubbed_credentials) { File.join(File.dirname(__FILE__), '..', 'fixtures') }
  before do
    Socialcast::CommandLine.stub(:config_dir).and_return(stubbed_credentials)
    HighLine.any_instance.stub(:say) 
  end
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
    describe 'when the file is missing' do
      before { Socialcast::CommandLine.stub(:credentials_file => "/does/not/exist") }
      it { expect { subject }.to raise_error(RuntimeError, 'Unknown Socialcast credentials.  Run `socialcast authenticate` to initialize') }
    end
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

  describe 'credential_obfuscation' do
    let(:clear_credentials) { { :username => "bob", :password => "foo" } }
    let(:opaque_credentials) { { :username => "bob", :password => "9671d40255f7d27b4bb536636491f84ddd6b90e0Zm9v" } } # "foo"

    describe '.obfuscate_credential_hash' do
      subject(:obfuscate_credential_hash) { Socialcast::CommandLine.send(:obfuscate_credential_hash, clear_credentials) }

      it "should obfuscate the password" do
        obfuscate_credential_hash[:password].should == opaque_credentials[:password]
      end

      it "should not change other values" do 
        (obfuscate_credential_hash.keys - [:password]).each { |k| obfuscate_credential_hash[k].should == clear_credentials[k] }
      end
    end

    describe '.clarify_credential_hash' do
      subject(:clarify_credential_hash) { Socialcast::CommandLine.send(:clarify_credential_hash, opaque_credentials) }

      it "should clarify the password" do
        clarify_credential_hash[:password].should == clear_credentials[:password]
      end

      it "should not change other values" do 
        (clarify_credential_hash.keys - [:password]).each { |k| clarify_credential_hash[k].should == opaque_credentials[k] }
      end

      context "with nonconformant password" do
        subject(:clarify_credential_hash) { Socialcast::CommandLine.send(:clarify_credential_hash, clear_credentials) }

        it "should use the literal value for the password" do
          clarify_credential_hash[:password].should == clear_credentials[:password]
        end

        it "should print a warning to standard out" do
          HighLine.any_instance.should_receive(:say).with(/Warning.*password.*decode/)
          clarify_credential_hash
        end
      end
    end
  end
end
