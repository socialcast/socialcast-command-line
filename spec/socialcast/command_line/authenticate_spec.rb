require 'spec_helper'

describe Socialcast::CommandLine::Authenticate do
  let(:options) { { :domain => "test.socialcast.local" } }
  let(:params) { {  } }
  subject(:authenticate) { Socialcast::CommandLine::Authenticate.new(authenticate_type, options, params) }

  describe '#request' do
    before do
      expect(RestClient::Resource).to receive(:new).with(url, {}).and_call_original
      expect_any_instance_of(RestClient::Resource).to receive(:post).with(subject.params, :accept => :json)
      expect(authenticate).to receive(:set_default_credentials).and_return(true)
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
    after do
      Socialcast::CommandLine::Authenticate.instance_variable_set(:@current_user, nil)
    end
    context 'as an unauthenticated user' do
      it { expect { current_user }.to raise_error(RuntimeError, 'Unknown Socialcast credentials.  Run `socialcast authenticate` to initialize') }
    end
    context 'with credentials specified out' do
      let(:stubbed_config_dir) { File.join(File.dirname(__FILE__), '..', '..', 'fixtures') }
      let(:current_user_stub) { { :user => { :id => 123 } } }
      let(:current_user_error) { { :error => "Failed to authenticate due to password" } }
      before { allow(Socialcast::CommandLine).to receive(:config_dir).and_return(stubbed_config_dir) }
      context 'as a successfull authenticated user' do
        before do
          stub_request(:get, "https://test.staging.socialcast.com/api/userinfo.json")
            .with(:basic_auth => ['ryan@socialcast.com', 'foo'])
            .to_return(:status => 200, :body => current_user_stub.to_json)
        end
        it { expect(current_user['id']).to eq(123) }
      end
      context 'when you not authenticated properly' do
        before do
          stub_request(:get, "https://test.staging.socialcast.com/api/userinfo.json")
            .with(:basic_auth => ['ryan@socialcast.com', 'foo'])
            .to_return(:status => 200, :body => current_user_error.to_json)
        end
        it { expect { current_user }.to raise_error(RuntimeError) }
      end
    end
  end
end
