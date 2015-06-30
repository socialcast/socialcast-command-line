require 'spec_helper'

describe Socialcast::CommandLine::ProvisionPhoto do
  let!(:ldap_with_profile_photo_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_profile_photo.yml')) }
  let!(:ldap_multiple_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_multiple_connection_mappings.yml')) }
  let!(:ldap_multiple_incomplete_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_multiple_incomplete_connection_mappings.yml')) }
  let(:default_profile_photo_id) { 3 }
  let(:another_profile_photo_id) { 4 }

  before do
    allow_any_instance_of(Socialcast::CommandLine::ProvisionPhoto).to receive(:default_profile_photo_id).and_return(default_profile_photo_id)
  end

  let(:ldap) do
    ldap_instance = double(Net::LDAP, :auth => nil, :encryption => nil)
    expect(ldap_instance).to receive(:open).and_yield
    expect(Net::LDAP).to receive(:new).and_return(ldap_instance)
    ldap_instance
  end

  describe '#sync' do
    context "with a single ldap connection" do
      let(:options) { {} }
      let(:provisioner) { Socialcast::CommandLine::ProvisionPhoto.new(ldap_with_profile_photo_config, options) }
      subject(:sync_photos) { provisioner.sync }
      let(:user_search_resource) { double(:user_search_resource) }
      let(:user_submit_resource) { double(:user_submit_resource) }
      let(:data_fingerprint) { '5d41402abc4b2a76b9719d911017c592' }
      let(:search_api_response) do
        {
          'users' => [
            {
              'id' => 7,
              'avatars' => {
                'id' => default_profile_photo_id
              },
              'contact_info' => {
                'email' => 'user@example.com'
              }
            }
          ]
        }
      end
      before do
        entry = create_entry 'user', :mail => 'user@example.com', :jpegPhoto => photo_data
        expect(ldap).to receive(:search).once.with(hash_including(:attributes => ['mail', 'jpegPhoto'])).and_yield(entry)
        allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)
      end

      context 'for when it does successfully post the photo' do
        before do
          expect(user_search_resource).to receive(:get).and_return(search_api_response.to_json)
          user_resource = double(:user_resource)
          expect(user_resource).to receive(:put) do |data|
            uploaded_data = data[:user][:profile_photo][:data]
            expect(uploaded_data.path).to match(/\.png\Z/)
          end
          allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/7', anything).and_return(user_resource)
        end
        context 'for a binary file' do
          let(:photo_data) { "\x89PNGabc" }
          before do
            expect(RestClient).not_to receive(:get)
            sync_photos
          end
          it 'uses the original binary to upload the photo' do end
        end
        context 'for an image file' do
          let(:photo_data) { "http://socialcast.com/someimage.png" }
          before do
            expect(RestClient).to receive(:get).with(photo_data).and_return("\x89PNGabc")
            sync_photos
          end
          it 'downloads the image form the web to upload the photo' do end
        end
      end

      context 'for when it does not successfully post the photo' do
        context 'for an image file' do
          let(:photo_data) { "http://socialcast.com/someimage.png" }
          before do
            expect(user_search_resource).to receive(:get).and_return(search_api_response.to_json)
            expect(RestClient).to receive(:get).with(photo_data).and_raise(RestClient::ResourceNotFound)
            sync_photos
          end
          it 'tries to download the image from the web and rescues 404' do end
        end
      end

      context 'when there is already a photo set' do
        before do
          allow_any_instance_of(Socialcast::CommandLine::ProvisionPhoto).to receive(:default_profile_photo_id).and_return(another_profile_photo_id)
        end
        let(:photo_data) { "\x89PNGabc" }
        before { expect(user_search_resource).to receive(:get).and_return(search_api_response.to_json) }
        context 'for a regular sync' do
          before do
            sync_photos
            expect(Socialcast::CommandLine).not_to receive(:resource_for_path)
          end
          it 'does not post the new photo' do end
        end
        context 'when they do a force sync' do
          let(:options) { { :force_sync => true } }
          before do
            expect(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/7', {}).and_return(user_submit_resource)
            expect(user_submit_resource).to receive(:put).and_return(true)
            sync_photos
          end
          it 'submits the photo anyways' do end
        end
      end
    end

    context "with multiple fully configured ldap connections" do
      let(:user_search_resource) { double(:user_search_resource) }
      let(:search_api_response) do
        {
          'users' => [
            {
              'id' => 7,
              'avatars' => {
                'id' => default_profile_photo_id
              },
              'contact_info' => {
                'email' => 'user@example.com'
              }
            },
            {
              'id' => 8,
              'avatars' => {
                'id' => default_profile_photo_id
              },
              'contact_info' => {
                'email' => 'user2@example.com'
              }
            }
          ]
        }
      end
      let(:provisioner) { Socialcast::CommandLine::ProvisionPhoto.new(ldap_multiple_connection_mapping_config, {}) }
      let(:sync_photos) { provisioner.sync }
      let(:binary_photo_data) { "\x89PNGabc".force_encoding('binary') }
      before do
        allow_any_instance_of(Socialcast::CommandLine::ProvisionPhoto::ApiSyncStrategy).to receive(:batch_size).and_return(2)

        ldap_instance1 = double(Net::LDAP, :encryption => nil, :auth => nil)
        expect(ldap_instance1).to receive(:open).and_yield
        expect(Net::LDAP).to receive(:new).once.ordered.and_return(ldap_instance1)
        entry1 = create_entry 'user', :mailCon => 'user@example.com', :photoCon => binary_photo_data
        expect(ldap_instance1).to receive(:search).once.with(hash_including(:attributes => ['mailCon', 'photoCon'])).and_yield(entry1)

        ldap_instance2 = double(Net::LDAP, :encryption => nil, :auth => nil)
        expect(ldap_instance2).to receive(:open).and_yield
        expect(Net::LDAP).to receive(:new).once.ordered.and_return(ldap_instance2)
        entry2 = create_entry 'user', :mailCon2 => 'user2@example.com', :photoCon2 => binary_photo_data
        expect(ldap_instance2).to receive(:search).once.with(hash_including(:attributes => ['mailCon2', 'photoCon2'])).and_yield(entry2)

        allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)

        expect(user_search_resource).to receive(:get).once.with({:params => { :q => "\"user@example.com\" OR \"user2@example.com\"", :per_page => 2}, :accept => :json}).and_return(search_api_response.to_json)

        user_resource1 = double(:user_resource)
        expect(user_resource1).to receive(:put) do |data|
          uploaded_data = data[:user][:profile_photo][:data]
          expect(uploaded_data.path).to match(/\.png\Z/)
        end
        allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/7', anything).and_return(user_resource1)

        user_resource2 = double(:user_resource)
        expect(user_resource2).to receive(:put) do |data|
          uploaded_data = data[:user][:profile_photo][:data]
          expect(uploaded_data.path).to match(/\.png\Z/)
        end
        allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/8', anything).and_return(user_resource2)

        sync_photos
      end
      it 'uses attributes from each connection' do end
      it 'is considered fully configured' do
        expect(provisioner.configured?).to be_truthy
      end
    end
    context "with multiple incompletely configured ldap connections" do
      let(:provisioner) { Socialcast::CommandLine::ProvisionPhoto.new(ldap_multiple_incomplete_connection_mapping_config, {}) }
      let(:sync_photos) { provisioner.sync }
      before do
        expect { sync_photos }.to raise_error Socialcast::CommandLine::Provisioner::ProvisionError
      end
      it 'is not considered fully configured' do
        expect(provisioner.configured?).to be_falsy
      end
      it 'provides a list of incomplete configurations' do
        expect(provisioner.unsupported_configurations).to eq(['example_connection_2'])
      end
    end
  end

  describe '.binary_to_content_type' do
    subject { Socialcast::CommandLine::ProvisionPhoto.new(ldap_with_profile_photo_config, {}).send(:binary_to_content_type, binary_photo_data) }
    let(:file_dir) { File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'test_images') }
    let(:binary_photo_data) { File.open(File.join(file_dir, image_name), 'rb') { |file| file.read } }
    context 'with a jpg' do
      let(:image_name) { 'test-jpg-image.jpg' }
      it { should == 'jpg' }
    end
    context 'with a gif' do
      let(:image_name) { 'test-gif-image.gif' }
      it { should == 'gif' }
    end
    context 'with a png' do
      let(:image_name) { 'test-png-image.png' }
      it { should == 'png' }
    end
    context 'with a tiff' do
      let(:image_name) { 'test-tiff-image.tiff' }
      it { should be_nil }
    end
  end
end
