require 'spec_helper'

describe Socialcast::CommandLine::ProvisionPhoto do
  let(:ldap_with_profile_photo) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_profile_photo.yml')) }

  context '#sync' do
    let(:options) { {} }
    subject(:sync_photos) { Socialcast::CommandLine::ProvisionPhoto.new(ldap_with_profile_photo, options).sync }
    let(:user_search_resource) { double(:user_search_resource) }
    let(:user_submit_resource) { double(:user_submit_resource) }
    let(:is_community_default) { true }
    let(:data_fingerprint) { '5d41402abc4b2a76b9719d911017c592' }
    let(:search_api_response) do
      {
        'users' => [
          {
            'id' => 7,
            'avatars' => {
              'is_community_default' => is_community_default,
              'data_fingerprint' => data_fingerprint
            }
          }
        ]
      }
    end
    before do
      entry = create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :jpegPhoto => photo_data
      Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'jpegPhoto', 'memberof'])).and_yield(entry)
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

    context 'when their is already a photo set' do
      let(:is_community_default) { false }
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


  context '.binary_to_content_type' do
    subject { Socialcast::CommandLine::ProvisionPhoto.new(ldap_with_profile_photo, {}).send(:binary_to_content_type, binary_photo_data) }
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
