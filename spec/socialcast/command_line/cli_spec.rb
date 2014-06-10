require 'spec_helper'

describe Socialcast::CommandLine::CLI do
  let(:credentials) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'credentials.yml')) }
  let(:ldap_default_config_file) { File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap.yml') }
  let(:ldap_with_profile_photo_config_file) { File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_profile_photo.yml') }
  let(:ldap_default_config) { YAML.load_file(ldap_default_config_file) }
  let(:ldap_with_array_permission_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_array_permission_mapping.yml')) }
  let(:ldap_with_interpolated_values_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_interpolated_values.yml')) }
  let(:ldap_with_manager_attribute_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_manager_attribute.yml')) }
  let(:ldap_with_plugin_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_plugin_mapping.yml')) }
  let(:ldap_with_profile_photo_config) { YAML.load_file(ldap_with_profile_photo_config_file) }
  let(:ldap_without_permission_mappings_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_without_permission_mappings.yml')) }
  let(:default_profile_photo_id) { 3 }
  let(:another_profile_photo_id) { 4 }

  before do
    Socialcast::CommandLine.stub(:credentials).and_return(credentials)
    Socialcast::CommandLine::ProvisionPhoto.any_instance.stub(:default_profile_photo_id).and_return(default_profile_photo_id)
  end

  let(:ldap) do
    ldap_instance = double(Net::LDAP, :auth => nil, :encryption => nil)
    ldap_instance.should_receive(:open).and_yield(ldap_instance)
    Net::LDAP.should_receive(:new).and_return(ldap_instance)
    ldap_instance
  end

  describe '#info' do
    before do
      Socialcast::CommandLine::CLI.any_instance.should_receive(:say).with("Socialcast Command Line #{Socialcast::CommandLine::VERSION}")
    end
    context '--version' do
      before do
        Socialcast::CommandLine::CLI.start ["--version"]
      end
      it "prints the version" do end
    end
    context '-v' do
      before do
        Socialcast::CommandLine::CLI.start ["-v"]
      end
      it "prints the version" do end
    end
  end

  describe '#authenticate' do
    let(:user) { 'mike@socialcast.com' }
    let(:password) { 'password' }
    let(:domain) { 'api.socialcast.com' }
    before do
      Socialcast::CommandLine.should_receive(:credentials=).with({
        :domain => 'api.socialcast.com',
        :proxy => nil
      })
      Socialcast::CommandLine.should_receive(:credentials=).with({
        :user => user,
        :password => password,
        :domain => domain
      })
      stub_request(:post, "https://api.socialcast.com/api/authentication").
         with(:body => {"email"=>"mike@socialcast.com", "password"=>"password"}).
         to_return(:status => 200, :body => { :communities => [{ :domain => domain }] }.to_json, :headers => {})
      Socialcast::CommandLine::CLI.start ['authenticate', "--user=#{user}", "--password=#{password}"]
    end
    ## See expectations
    it 'authenticates with the API and sets the given credentials' do end
  end

  describe '#authenticate_external_system' do
    let(:api_client_identifier) { 'my-client-id' }
    let(:api_client_secret) { 'my-client-secret' }
    let(:domain) { 'api.socialcast.com' }
    before do
      Socialcast::CommandLine.should_receive(:credentials=).with({
        :domain => 'api.socialcast.com',
        :proxy => nil
      })
      Socialcast::CommandLine.should_receive(:credentials=).with({
        :api_client_identifier => api_client_identifier,
        :api_client_secret => api_client_secret,
      })
      stub_request(:post, "https://api.socialcast.com/api/external_systems/authentication").
         with(:headers => {'Authorization'=>'SocialcastApiClient my-client-id:my-client-secret'}).
         to_return(:status => 200, :body => "", :headers => {})
      Socialcast::CommandLine::CLI.start ['authenticate_external_system', "--api_client_identifier=#{api_client_identifier}", "--api_client_secret=#{api_client_secret}"]
    end
    ## See expectations
    it 'authenticates with the API and sets the given credentials for an authenticated system' do end
  end

  describe '#share' do
    # Expects -u=emily@socialcast.com -p=demo --domain=demo.socialcast.com
    context 'with a basic message' do
      before do
        stub_request(:post, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/messages.json").
                 with(:body => { "message" => { "body" => "testing", "url" => nil, "message_type" => nil, "attachment_ids" => [], "group_id" => nil }}).
                 with(:headers => {'Accept' => 'application/json'}).
                 to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CommandLine::CLI.start ['share', 'testing']
      end
      it 'should send a POST with a message body of "testing" and nil message-type' do
        # See expectations
      end
    end

    context 'with a message_type message' do
      before do
        stub_request(:post, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/messages.json").
                 with(:body => /message\_type\"\:review\_request/).
                 with(:body => /please\sreview/).
                 with(:headers => {'Accept' => 'application/json'}).
                 to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CommandLine::CLI.start ['share', 'please review', '--message_type=review_request']
      end
      it 'should send a POST with a message body of "please review" and message_type of "review_request"' do
        # See expectations
      end
    end
    context 'with a group_id param' do
      before do
        stub_request(:post, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/messages.json").
                 with(:body => /group\_id\"\:123/).
                 with(:headers => {'Accept' => 'application/json'}).
                 to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CommandLine::CLI.start ['share', 'hi', '--group_id=123']
      end
      it 'should send a POST with group_id param == 123' do
        # See expectations
      end
    end
    context "with a proxy" do
      before do
        stub_request(:post, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/messages.json").
                 with(:body => /message\_type\"\:null/).
                 with(:body => /testing/).
                 with(:headers => {'Accept' => 'application/json'}).
                 to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CommandLine::CLI.start ['share', 'testing']
      end
      it 'should send a POST with a message body of "testing" and nil message-type' do
        # See expectations
      end
    end
  end

  describe '#sync_photos' do
    context "with no profile_photo mapping" do
      let(:config_file) { ldap_default_config_file }
      it "reports an error" do
        lambda { Socialcast::CommandLine::CLI.start ['sync_photos', '-c', config_file] }.should raise_error KeyError
      end
    end

    context "user does not have a profile photo" do
      let(:config_file) { ldap_with_profile_photo_config_file }
      let(:photo_data) { "\x89PNGabc".force_encoding('binary') }
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:jpegPhoto] = photo_data
        ldap.should_receive(:search).and_yield(@entry)

        user_search_resource = double(:user_search_resource)
        search_api_response = {
          'users' => [
            {
              'id' => 7,
              'avatars' => {
                'id' => default_profile_photo_id
              },
              'contact_info' => {
                'email' => 'ryan@example.com'
              }
            }
          ]
        }
        user_search_resource.should_receive(:get).and_return(search_api_response.to_json)
        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)

        user_resource = double(:user_resource)
        user_resource.should_receive(:put) do |data|
          uploaded_data = data[:user][:profile_photo][:data]
          uploaded_data.read.force_encoding('binary').should == photo_data
          uploaded_data.path.should =~ /\.png\Z/
        end
        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/7', anything).and_return(user_resource)

        Socialcast::CommandLine::CLI.start ['sync_photos', '-c', config_file]
      end
      it "syncs the profile photo" do; end
    end

    context "unknown image format" do
      let(:config_file) { ldap_with_profile_photo_config_file }
      let(:photo_data) { "abc" }
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:jpegPhoto] = photo_data
        ldap.should_receive(:search).and_yield(@entry)

        user_search_resource = double(:user_search_resource)
        search_api_response = {
          'users' => [
            {
              'id' => 7,
              'avatars' => {
                'id' => default_profile_photo_id
              }
            }
          ]
        }
        user_search_resource.should_receive(:get).and_return(search_api_response.to_json)
        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)

        user_resource = double(:user_resource)
        user_resource.should_not_receive(:put)
        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/7', anything).and_return(user_resource)

        Socialcast::CommandLine::CLI.start ['sync_photos', '-c', config_file]
      end
      it "does not sync the profile photo" do; end
    end

    context "user already has a profile photo" do
      let(:config_file) { ldap_with_profile_photo_config_file }
      let(:photo_data) { "\x89PNGabc".force_encoding('binary') }
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:jpegPhoto] = photo_data
        ldap.should_receive(:search).and_yield(@entry)

        user_search_resource = double(:user_search_resource)
        search_api_response = {
          'users' => [
            {
              'id' => 7,
              'avatars' => {
                'id' => another_profile_photo_id
              }
            }
          ]
        }
        user_search_resource.should_receive(:get).and_return(search_api_response.to_json)
        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)

        user_resource = double(:user_resource)
        user_resource.should_not_receive(:put)
        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/7', anything).and_return(user_resource)

        Socialcast::CommandLine::CLI.start ['sync_photos', '-c', config_file]
      end
      it "does not sync the profile photo" do; end
    end
  end

  describe '#provision' do
    before do
      Socialcast::CommandLine::CLI.instance_eval do # to supress warning from stubbing ldap_config
        @no_tasks = @no_commands = true
      end
    end
    context 'with 0 users found in ldap' do
      before do
        ldap.should_receive(:search).and_return(nil)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_without_permission_mappings_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.should_not_receive(:post)
      end
      it 'does not post to Socialcast and raises error' do
        lambda { Socialcast::CommandLine::CLI.start ['provision'] }.should raise_error SystemExit
      end
    end
    context 'with 0 users found in ldap and force option passed' do
      before do
        ldap.should_receive(:search).and_return(nil)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_without_permission_mappings_config)

        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.should_receive(:post).once

        Socialcast::CommandLine::CLI.start ['provision', '-f']
      end
      it 'does post to Socialcast and does not raise error' do end # see expectations
    end
    context 'with socialcast returning 401' do
      before do
        ldap.should_receive(:search).and_return(nil)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_without_permission_mappings_config)

        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        rest_client_resource = double(:rest_client_resource)
        rest_client_resource.stub(:post).and_raise(RestClient::Unauthorized.new(double('Unauthorized HTTP Response', :code => '401', :body => 'Unauthorized HTTP Response')))
        Socialcast::CommandLine.stub(:resource_for_path).and_return(rest_client_resource)
        Kernel.should_receive(:abort).with("Authenticated user either does not have administration privileges or the community is not configured to allow provisioning. Please contact Socialcast support to if you need help.").once

        Socialcast::CommandLine::CLI.start ['provision', '-f']
      end
      it "raises Kernel abort" do end # see expectations
    end
    context 'with absolute path to ldap.yml file' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        ldap.should_receive(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).with(hash_including('config' => '/my/path/to/ldap.yml')).and_return(ldap_without_permission_mappings_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CommandLine::CLI.start ['provision', '-c', '/my/path/to/ldap.yml']
      end
      it 'resolves absolute path without using current process directory' do end # see expectations
    end
    context 'with plugins option used with non-existent ruby files' do
      it 'does not post to Socialcast and raises an error' do
        lambda { Socialcast::CommandLine::CLI.start ['provision', '-c', '/my/path/to/ldap.yml', '--plugins', ['does_not_exist.rb', 'also_does_not_exist.rb']] }.should raise_error
      end
    end
    context 'with plugins option used with existent ruby file' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:plugin_attr] = 'some value'
        ldap.should_receive(:search).with(hash_including(:attributes => ['plugin_attr', 'sn', 'mail', 'memberof'])).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_with_plugin_mapping_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CommandLine::CLI.start ['provision', '--plugins', [File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'fake_attribute_map')]]
      end
      it 'successfully processes' do
        @result.should =~ %r{some vblue}
      end # see expectations
    end
    context 'with ldap.yml configuration excluding permission_mappings' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'

        ldap.should_receive(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_without_permission_mappings_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end
      it 'excludes roles element' do
        @result.should_not =~ %r{roles}
      end
    end
    context 'with external group member' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=External,dc=example,dc=com'

        ldap.should_receive(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_default_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end
      it 'sets account-type to external' do
        @result.should =~ %r{<account-type>external</account-type>}
      end
    end
    context 'with multiple possible external group member' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=Contractor,dc=example,dc=com'

        ldap.should_receive(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_with_array_permission_mapping_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end
      it 'sets account-type to external' do
        @result.should =~ %r{<account-type>external</account-type>}
      end
    end

    context 'with tenant_admin group member' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=Admins,dc=example,dc=com'

        ldap.should_receive(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_default_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end
      it 'sets account-type to member' do
        @result.should =~ %r{<account-type>member</account-type>}
      end
      it 'adds tenant_admin role' do
        @result.should =~ %r{<role>tenant_admin</role>}
      end
    end
    context 'entry isMemberOf Marketing group' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=Marketing,dc=example,dc=com'

        ldap.should_receive(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_with_array_permission_mapping_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CommandLine::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
      end
      it 'sets account-type to member' do
        @result.should =~ %r{<account-type>member</account-type>}
      end
      it 'adds sbi_admin role' do
        @result.should =~ %r{<role>sbi_admin</role>}
      end
    end
    context 'entry isMemberOf Engineering group' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=Engineering,dc=example,dc=com'

        ldap.should_receive(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_with_array_permission_mapping_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end
      it 'sets account-type to member' do
        @result.should =~ %r{<account-type>member</account-type>}
      end
      it 'adds sbi_admin role' do
        @result.should =~ %r{<role>sbi_admin</role>}
      end
    end

    context 'with ldap.yml configuration including template value' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:l] = 'San Francisco'
        @entry[:co] = 'USA'

        ldap.should_receive(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_with_interpolated_values_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end

      it 'formats l and co according to template' do
        @result.should =~ %r{<location>San Francisco, USA</location>}
      end
    end

    context 'with ldap.yml configuration including manager attribute mapping' do
      let(:result) { '' }
      before do
        employee_entry = Net::LDAP::Entry.new("cn=employee,dc=example,dc=com")
        employee_entry[:mail] = 'employee@example.com'
        employee_entry[:ldap_manager] = 'cn=manager,dc=example,dc=com'
        manager_entry = Net::LDAP::Entry.new("cn=manager,dc=example,dc=com")
        manager_entry[:mail] = 'manager@example.com'

        ldap.should_receive(:search).once.ordered.and_yield(manager_entry).and_yield(employee_entry)
        ldap.should_receive(:search).once.ordered.and_yield(manager_entry).and_yield(employee_entry)

        Zlib::GzipWriter.stub(:open).and_yield(result)
        Socialcast::CommandLine::CLI.any_instance.should_receive(:ldap_config).and_return(ldap_with_manager_attribute_config)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CommandLine::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
      end

      it 'adds a manager_email entry of bossman@example.com' do
        result.should =~ /<email>employee@example.com<\/email>/
        result.should =~ /<label>manager_email<\/label>\s*<value>manager@example.com<\/value>/
      end
    end
  end
end
