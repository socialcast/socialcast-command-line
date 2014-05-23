require 'spec_helper'

describe Socialcast::CommandLine::ProvisionPhoto do
  let!(:ldap_with_profile_photo) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_profile_photo.yml')) }

  describe '#sync_photos' do
    let(:user_search_resource) { double(:user_search_resource) }
    let(:search_api_response) do
      {
        'users' => [
          {
            'id' => 7,
            'avatars' => {
              'is_system_default' => true
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
    let(:sync_photos) { Socialcast::CommandLine::ProvisionPhoto.new(ldap_with_profile_photo, {}).sync }

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
        context 'when it successfully downloads' do
          before do
            RestClient.should_receive(:get).with(photo_data).and_return("\x89PNGabc")
            sync_photos
          end
          it 'downloads the image form the web to upload the photo' do end
        end
      end
    end

    context 'for when it does not successfully post the photo' do
      context 'for an image file' do
        let(:photo_data) { "http://socialcast.com/someimage.png" }
        before do
          user_search_resource.should_receive(:get).and_return({ :users => [{ :avatars => { :is_system_default => true }}] }.to_json)
          RestClient.should_receive(:get).with(photo_data).and_raise(RestClient::ResourceNotFound)
          sync_photos
        end
        it 'tries to download the image from the web and rescues 404' do end
      end
    end
  end
end
