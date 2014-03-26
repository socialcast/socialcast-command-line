require 'spec_helper'

describe Socialcast::CommandLine do

  let(:custom_file) { File.join(File.dirname(__FILE__), '..', 'fixtures', 'custom_credentials.yml') }
  let(:stubbed_credentials) { File.join(File.dirname(__FILE__), '..', 'fixtures') }
  before { Socialcast::CommandLine.stub(:config_dir).and_return(stubbed_credentials) }

  describe '#credentials_file' do
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

  describe '#credentials' do
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

end
