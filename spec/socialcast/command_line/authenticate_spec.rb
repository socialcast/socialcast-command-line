require 'spec_helper'

describe Socialcast::CommandLine::Authenticate do
  let(:options) { { :domain => "test.socialcast.local" } }
  let(:params) { {  } }
  subject { Socialcast::CommandLine::Authenticate.new(authenticate_type, options, params) }

  describe '#request' do
    before do
      RestClient::Resource.should_receive(:new).with(url).and_call_original
      RestClient::Resource.any_instance.should_receive(:post).with(subject.params, :accept => :json)
      subject.request
    end
    context 'for a regular user' do
      let(:authenticate_type) { :user }
      let(:url) { "https://test.socialcast.local/api/authentication" }
      it 'hits the API to try authentication for a regular user' do end
    end

    context 'for an external system' do
      let(:url) { "https://test.socialcast.local/api/external_systems/authentication" }
      let(:authenticate_type) { :external_system }
      it 'hits the API to try authentication for an external system' do end
    end
  end

end
