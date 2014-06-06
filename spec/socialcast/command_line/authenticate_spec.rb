require 'spec_helper'

describe Socialcast::CommandLine::Authenticate do
  let(:options) { { :domain => "test.socialcast.local" } }
  let(:params) { {  } }
  subject(:authenticate) { Socialcast::CommandLine::Authenticate.new(authenticate_type, options, params) }

  describe '#request' do
    before do
      RestClient::Resource.should_receive(:new).with(url, {}).and_call_original
      RestClient::Resource.any_instance.should_receive(:post).with(subject.params, :accept => :json)
      authenticate.should_receive(:set_default_credentials).and_return(true)
      authenticate.request
    end
    context 'for a regular user' do
      let(:authenticate_type) { :user }
      let(:url) { "https://test.socialcast.local/api/authentication" }
      # See expectations
      it 'hits the API to try authentication for a regular user' do end
    end

    context 'for an external system' do
      let(:url) { "https://test.socialcast.local/api/external_systems/authentication" }
      let(:authenticate_type) { :external_system }
      # See expectations
      it 'hits the API to try authentication for an external system' do end
    end
  end

  describe '.current_user' do
    subject(:current_user) { Socialcast::CommandLine::Authenticate.current_user }
    context 'as an unauthenticated user' do
      it { expect { current_user }.to raise_error(RuntimeError, 'Unknown Socialcast credentials.  Run `socialcast authenticate` to initialize') }
    end
    context 'as an authenticated user' do
      let(:stubbed_config_dir) { File.join(File.dirname(__FILE__), '..', '..', 'fixtures') }
      let(:current_user_stub) do
        {
          :user => { :id => 123 }
        }
      end
      before do
        Socialcast::CommandLine.stub(:config_dir).and_return(stubbed_config_dir)
        stub_request(:get, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/userinfo.json").
          to_return(:status => 200, :body => current_user_stub.to_json)
      end
      it { current_user['id'].should == 123 }
    end
  end
end
