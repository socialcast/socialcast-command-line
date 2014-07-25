require 'spec_helper'

describe Socialcast::CommandLine::ProvisionPhoto do
  let!(:ldap_with_profile_photo_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_profile_photo.yml')) }
  let!(:ldap_multiple_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_multiple_connection_mappings.yml')) }
  let(:default_profile_photo_id) { 3 }
  let(:another_profile_photo_id) { 4 }

  before do
    Socialcast::CommandLine::ProvisionPhoto.any_instance.stub(:default_profile_photo_id).and_return(default_profile_photo_id)
  end

  let(:ldap) do
    ldap_instance = double(Net::LDAP, :auth => nil, :encryption => nil)
    ldap_instance.should_receive(:open).and_yield
    Net::LDAP.should_receive(:new).and_return(ldap_instance)
    ldap_instance
  end

  describe '#sync' do
    context "with a single ldap connection" do
      let(:options) { {} }
      subject(:sync_photos) { Socialcast::CommandLine::ProvisionPhoto.new(ldap_with_profile_photo_config, options).sync }
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
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['mail', 'jpegPhoto'])).and_yield(entry)
        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)
      end

      context 'for when it does successfully post the photo' do
        before do
          user_search_resource.should_receive(:get).and_return(search_api_response.to_json)
          user_resource = double(:user_resource)
          user_resource.should_receive(:put) do |data|
            uploaded_data = data[:user][:profile_photo][:data]
            uploaded_data.path.should =~ /\.png\Z/
          end
          Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/7', anything).and_return(user_resource)
        end
        context 'for a binary file' do
          let(:photo_data) { "\x89PNGabc" }
          before do
            RestClient.should_not_receive(:get)
            sync_photos
          end
          it 'uses the original binary to upload the photo' do end
        end
        context 'for an image file' do
          let(:photo_data) { "http://socialcast.com/someimage.png" }
          before do
            RestClient.should_receive(:get).with(photo_data).and_return("\x89PNGabc")
            sync_photos
          end
          it 'downloads the image form the web to upload the photo' do end
        end
      end

      context 'for when it does not successfully post the photo' do
        context 'for an image file' do
          let(:photo_data) { "http://socialcast.com/someimage.png" }
          before do
            user_search_resource.should_receive(:get).and_return(search_api_response.to_json)
            RestClient.should_receive(:get).with(photo_data).and_raise(RestClient::ResourceNotFound)
            sync_photos
          end
          it 'tries to download the image from the web and rescues 404' do end
        end
      end

      context 'when there is already a photo set' do
        before do
          Socialcast::CommandLine::ProvisionPhoto.any_instance.stub(:default_profile_photo_id).and_return(another_profile_photo_id)
        end
        let(:photo_data) { "\x89PNGabc" }
        before { user_search_resource.should_receive(:get).and_return(search_api_response.to_json) }
        context 'for a regular sync' do
          before do
            sync_photos
            Socialcast::CommandLine.should_not_receive(:resource_for_path)
          end
          it 'does not post the new photo' do end
        end
        context 'when they do a force sync' do
          let(:options) { { :force_sync => true } }
          before do
            Socialcast::CommandLine.should_receive(:resource_for_path).with('/api/users/7', {}).and_return(user_submit_resource)
            user_submit_resource.should_receive(:put).and_return(true)
            sync_photos
          end
          it 'submits the photo anyways' do end
        end
      end
    end

    context "with multiple ldap connections" do
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

      let(:sync_photos) { Socialcast::CommandLine::ProvisionPhoto.new(ldap_multiple_connection_mapping_config, {}).sync }
      let(:binary_photo_data) { "\x89PNGabc".force_encoding('binary') }
      before do
        Socialcast::CommandLine::ProvisionPhoto::ApiSyncStrategy.any_instance.stub(:batch_size).and_return(2)

        ldap_instance1 = double(Net::LDAP, :encryption => nil, :auth => nil)
        ldap_instance1.should_receive(:open).and_yield
        Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance1)
        entry1 = create_entry 'user', :mailCon => 'user@example.com', :photoCon => binary_photo_data
        ldap_instance1.should_receive(:search).once.with(hash_including(:attributes => ['mailCon', 'photoCon'])).and_yield(entry1)

        ldap_instance2 = double(Net::LDAP, :encryption => nil, :auth => nil)
        ldap_instance2.should_receive(:open).and_yield
        Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance2)
        entry2 = create_entry 'user', :mailCon2 => 'user2@example.com', :photoCon2 => binary_photo_data
        ldap_instance2.should_receive(:search).once.with(hash_including(:attributes => ['mailCon2', 'photoCon2'])).and_yield(entry2)

        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)

        user_search_resource.should_receive(:get).once.with({:params => { :q => "\"user@example.com\" OR \"user2@example.com\"", :per_page => 2}, :accept => :json}).and_return(search_api_response.to_json)

        user_resource1 = double(:user_resource)
        user_resource1.should_receive(:put) do |data|
          uploaded_data = data[:user][:profile_photo][:data]
          uploaded_data.path.should =~ /\.png\Z/
        end
        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/7', anything).and_return(user_resource1)

        user_resource2 = double(:user_resource)
        user_resource2.should_receive(:put) do |data|
          uploaded_data = data[:user][:profile_photo][:data]
          uploaded_data.path.should =~ /\.png\Z/
        end
        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/8', anything).and_return(user_resource2)

        sync_photos
      end
      it 'uses attributes from each connection' do end
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
