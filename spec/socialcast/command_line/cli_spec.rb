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
    allow(Socialcast::CommandLine).to receive(:credentials).and_return(credentials)
    allow_any_instance_of(Socialcast::CommandLine::ProvisionPhoto).to receive(:default_profile_photo_id).and_return(default_profile_photo_id)
  end

  let(:ldap) do
    ldap_instance = double(Net::LDAP, :auth => nil, :encryption => nil)
    expect(ldap_instance).to receive(:open).and_yield
    expect(Net::LDAP).to receive(:new).and_return(ldap_instance)
    ldap_instance
  end

  describe '#info' do
    before do
      expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:say).with("Socialcast Command Line #{Socialcast::CommandLine::VERSION}")
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
    let(:default_domain) { 'api.socialcast.com' }
    let(:first_tenant_domain) { 'test1.socialcast.com' }
    let(:second_tenant_domain) { 'test2.socialcast.com' }
    before do
      expect(Socialcast::CommandLine).to receive(:credentials=).with({
        :domain => default_domain,
        :proxy => nil
      })
      expect(Socialcast::CommandLine).to receive(:credentials=).with({
        :user => user,
        :password => password,
        :domain => domain_to_set
      })
      stub_request(:post, "https://#{default_domain}/api/authentication").
         with(:body => {"email"=>"mike@socialcast.com", "password"=>"password"}).
         to_return(:status => 200, :body => { :communities => [ { :domain => first_tenant_domain }, { :domain => second_tenant_domain }] }.to_json, :headers => {})
    end
    context 'when passed a domain directly' do
      let(:domain_to_set) { second_tenant_domain }
      let(:default_domain) { second_tenant_domain }
      before do
        Socialcast::CommandLine::CLI.start ['authenticate', "--user=#{user}", "--password=#{password}", "--domain=#{second_tenant_domain}"]
      end
       #See expectations
      it 'authenticates with the API and sets the domain to the domain passed as an option' do end
    end
    context 'when not passed a domain it chooses the first domain returned from the response' do
      let(:domain_to_set) { first_tenant_domain }
      before do
        Socialcast::CommandLine::CLI.start ['authenticate', "--user=#{user}", "--password=#{password}"]
      end
      ## See expectations
      it 'authenticates with the API and sets the domain to the first domain returned' do end
    end
  end

  describe '#authenticate_external_system' do
    let(:api_client_identifier) { 'my-client-id' }
    let(:api_client_secret) { 'my-client-secret' }
    let(:domain) { 'api.socialcast.com' }
    before do
      expect(Socialcast::CommandLine).to receive(:credentials=).with({
        :domain => 'api.socialcast.com',
        :proxy => nil
      })
      expect(Socialcast::CommandLine).to receive(:credentials=).with({
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
        stub_request(:post, "https://test.staging.socialcast.com/api/messages.json").
                 with(:basic_auth => ['ryan@socialcast.com', 'foo'], :body => { "message" => { "body" => "testing", "url" => nil, "message_type" => nil, "attachment_ids" => [], "group_id" => nil }}).
                 with(:headers => {'Accept' => 'application/json'}).
                 to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CommandLine::CLI.start ['share', 'testing']
      end
      it 'should send a POST with a message body of "testing" and nil message-type' do
        # See expectations
      end
    end

    context 'with response data' do
      before do
        message_request_data =  {
          'message' => {
            'body' => 'testing',
            'url' => nil,
            'message_type' => nil,
            'attachment_ids' => [],
            'group_id' => nil
          }
        }
        message_response_data = {
          'message' => message_request_data['message'].merge(
            'id' => 123,
            'permalink_url' => 'https://test.stagings.socialcast.com/messages/123'
          )
        }
        stub_request(:post, "https://test.staging.socialcast.com/api/messages.json")
          .with(:basic_auth => ['ryan@socialcast.com', 'foo'])
          .with(:body => message_request_data)
          .with(:headers => {'Accept' => 'application/json'})
          .to_return(:status => 200, :body => message_response_data.to_json, :headers => {})
      end
      it do
        message_object = nil
        expect(Socialcast::CommandLine::Message).to receive(:create).and_wrap_original do |method, *args|
          message_object = method.call(*args)
        end
        Socialcast::CommandLine::CLI.start ['share', 'testing']
        expect(message_object.permalink_url).to eq 'https://test.stagings.socialcast.com/messages/123'
        expect(message_object['permalink_url']).to eq 'https://test.stagings.socialcast.com/messages/123'
      end
    end

    context 'with a message_type message' do
      before do
        stub_request(:post, "https://test.staging.socialcast.com/api/messages.json")
                .with(:basic_auth => ['ryan@socialcast.com', 'foo'])
                .with(:body => /message\_type\"\:review\_request/)
                .with(:body => /please\sreview/)
                .with(:headers => {'Accept' => 'application/json'})
                .to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CommandLine::CLI.start ['share', 'please review', '--message_type=review_request']
      end
      it 'should send a POST with a message body of "please review" and message_type of "review_request"' do
        # See expectations
      end
    end
    context 'with a group_id param' do
      before do
        stub_request(:post, "https://test.staging.socialcast.com/api/messages.json")
                .with(:basic_auth => ['ryan@socialcast.com', 'foo'])
                .with(:body => /group\_id\"\:123/)
                .with(:headers => {'Accept' => 'application/json'})
                .to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CommandLine::CLI.start ['share', 'hi', '--group_id=123']
      end
      it 'should send a POST with group_id param == 123' do
        # See expectations
      end
    end
    context "with a proxy" do
      before do
        stub_request(:post, "https://test.staging.socialcast.com/api/messages.json")
                .with(:basic_auth => ['ryan@socialcast.com', 'foo'])
                .with(:body => /message\_type\"\:null/)
                .with(:body => /testing/)
                .with(:headers => {'Accept' => 'application/json'})
                .to_return(:status => 200, :body => "", :headers => {})

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
        expect { Socialcast::CommandLine::CLI.start ['sync_photos', '-c', config_file] }.to raise_error Socialcast::CommandLine::Provisioner::ProvisionError
      end
    end

    context "user does not have a profile photo" do
      let(:config_file) { ldap_with_profile_photo_config_file }
      let(:photo_data) { "\x89PNGabc".force_encoding('binary') }
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:jpegPhoto] = photo_data
        expect(ldap).to receive(:search).and_yield(@entry)

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
        expect(user_search_resource).to receive(:get).and_return(search_api_response.to_json)
        allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)

        user_resource = double(:user_resource)
        expect(user_resource).to receive(:put) do |data|
          uploaded_data = data[:user][:profile_photo][:data]
          expect(uploaded_data.read.force_encoding('binary')).to eq(photo_data)
          expect(uploaded_data.path).to match(/\.png\Z/)
        end
        allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/7', anything).and_return(user_resource)

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
        expect(ldap).to receive(:search).and_yield(@entry)

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
        expect(user_search_resource).to receive(:get).and_return(search_api_response.to_json)
        allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)

        user_resource = double(:user_resource)
        expect(user_resource).not_to receive(:put)
        allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/7', anything).and_return(user_resource)

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
        expect(ldap).to receive(:search).and_yield(@entry)

        user_search_resource = double(:user_search_resource)
        search_api_response = {
          'users' => [
            {
              'id' => 7,
              'avatars' => {
                'id' => another_profile_photo_id
              },
              'contact_info' => {
                'email' => 'ryan@example.com'
              }
            }
          ]
        }
        expect(user_search_resource).to receive(:get).and_return(search_api_response.to_json)
        allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)

        user_resource = double(:user_resource)
        expect(user_resource).not_to receive(:put)
        allow(Socialcast::CommandLine).to receive(:resource_for_path).with('/api/users/7', anything).and_return(user_resource)

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
        expect(ldap).to receive(:search).and_return(nil)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_without_permission_mappings_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)

        expect_any_instance_of(RestClient::Resource).not_to receive(:post)
      end
      it 'does not post to Socialcast and raises error' do
        expect { Socialcast::CommandLine::CLI.start ['provision'] }.to raise_error SystemExit
      end
    end
    context 'with 0 users found in ldap and force option passed' do
      before do
        expect(ldap).to receive(:search).and_return(nil)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_without_permission_mappings_config)

        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)

        expect_any_instance_of(RestClient::Resource).to receive(:post).once

        Socialcast::CommandLine::CLI.start ['provision', '-f']
      end
      it 'does post to Socialcast and does not raise error' do end # see expectations
    end
    context 'with socialcast returning 401' do
      before do
        expect(ldap).to receive(:search).and_return(nil)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_without_permission_mappings_config)

        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)
        rest_client_resource = double(:rest_client_resource)
        allow(rest_client_resource).to receive(:post).and_raise(RestClient::Unauthorized.new(double('Unauthorized HTTP Response', :code => '401', :body => 'Unauthorized HTTP Response')))
        allow(Socialcast::CommandLine).to receive(:resource_for_path).and_return(rest_client_resource)
        expect(Kernel).to receive(:abort).with(an_instance_of(String)).once

        Socialcast::CommandLine::CLI.start ['provision', '-f']
      end
      it "raises Kernel abort" do end # see expectations
    end
    context 'with absolute path to ldap.yml file' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        expect(ldap).to receive(:search).and_yield(@entry)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).with(hash_including('config' => '/my/path/to/ldap.yml')).and_return(ldap_without_permission_mappings_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)
        allow_any_instance_of(RestClient::Resource).to receive(:post)

        Socialcast::CommandLine::CLI.start ['provision', '-c', '/my/path/to/ldap.yml']
      end
      it 'resolves absolute path without using current process directory' do end # see expectations
    end
    context 'with plugins option used with non-existent ruby files' do
      it 'does not post to Socialcast and raises an error' do
        expect { Socialcast::CommandLine::CLI.start ['provision', '-c', '/my/path/to/ldap.yml', '--plugins', ['does_not_exist.rb', 'also_does_not_exist.rb']] }.to raise_error
      end
    end
    context 'with plugins option used with existent ruby file' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:plugin_attr] = 'some value'
        expect(ldap).to receive(:search).with(hash_including(:attributes => ['plugin_attr', 'sn', 'mail', 'memberof'])).and_yield(@entry)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_with_plugin_mapping_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)
        allow_any_instance_of(RestClient::Resource).to receive(:post)

        Socialcast::CommandLine::CLI.start ['provision', '--plugins', [File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'fake_attribute_map')]]
      end
      it 'successfully processes' do
        expect(@result).to match(%r{some vblue})
      end # see expectations
    end
    context 'with ldap.yml configuration excluding permission_mappings' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'

        expect(ldap).to receive(:search).and_yield(@entry)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_without_permission_mappings_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)

        allow_any_instance_of(RestClient::Resource).to receive(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end
      it 'excludes roles element' do
        expect(@result).not_to match(%r{roles})
      end
    end
    context 'with external group member' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=External,dc=example,dc=com'

        expect(ldap).to receive(:search).and_yield(@entry)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_default_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)

        allow_any_instance_of(RestClient::Resource).to receive(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end
      it 'sets account-type to external' do
        expect(@result).to match(%r{<account-type>external</account-type>})
      end
    end
    context 'with multiple possible external group member' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=Contractor,dc=example,dc=com'

        expect(ldap).to receive(:search).and_yield(@entry)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_with_array_permission_mapping_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)

        allow_any_instance_of(RestClient::Resource).to receive(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end
      it 'sets account-type to external' do
        expect(@result).to match(%r{<account-type>external</account-type>})
      end
    end

    context 'with tenant_admin group member' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=Admins,dc=example,dc=com'

        expect(ldap).to receive(:search).and_yield(@entry)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_default_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)

        allow_any_instance_of(RestClient::Resource).to receive(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end
      it 'sets account-type to member' do
        expect(@result).to match(%r{<account-type>member</account-type>})
      end
      it 'adds tenant_admin role' do
        expect(@result).to match(%r{<role>tenant_admin</role>})
      end
    end
    context 'entry isMemberOf Marketing group' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=Marketing,dc=example,dc=com'

        expect(ldap).to receive(:search).and_yield(@entry)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_with_array_permission_mapping_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)

        allow_any_instance_of(RestClient::Resource).to receive(:post)

        Socialcast::CommandLine::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
      end
      it 'sets account-type to member' do
        expect(@result).to match(%r{<account-type>member</account-type>})
      end
      it 'adds sbi_admin role' do
        expect(@result).to match(%r{<role>sbi_admin</role>})
      end
    end
    context 'entry isMemberOf Engineering group' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=Engineering,dc=example,dc=com'

        expect(ldap).to receive(:search).and_yield(@entry)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_with_array_permission_mapping_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)

        allow_any_instance_of(RestClient::Resource).to receive(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end
      it 'sets account-type to member' do
        expect(@result).to match(%r{<account-type>member</account-type>})
      end
      it 'adds sbi_admin role' do
        expect(@result).to match(%r{<role>sbi_admin</role>})
      end
    end

    context 'with ldap.yml configuration including template value' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:l] = 'San Francisco'
        @entry[:co] = 'USA'

        expect(ldap).to receive(:search).and_yield(@entry)

        @result = ''
        allow(Zlib::GzipWriter).to receive(:open).and_yield(@result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_with_interpolated_values_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)

        allow_any_instance_of(RestClient::Resource).to receive(:post)

        Socialcast::CommandLine::CLI.start ['provision']
      end

      it 'formats l and co according to template' do
        expect(@result).to match(%r{<location>San Francisco, USA</location>})
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

        expect(ldap).to receive(:search).once.ordered.and_yield(manager_entry).and_yield(employee_entry)
        expect(ldap).to receive(:search).once.ordered.and_yield(manager_entry).and_yield(employee_entry)

        allow(Zlib::GzipWriter).to receive(:open).and_yield(result)
        expect_any_instance_of(Socialcast::CommandLine::CLI).to receive(:ldap_config).and_return(ldap_with_manager_attribute_config)
        allow(File).to receive(:open).with(/users.xml.gz/, anything).and_yield(@result)

        allow_any_instance_of(RestClient::Resource).to receive(:post)

        Socialcast::CommandLine::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
      end

      it 'adds a manager_email entry of bossman@example.com' do
        expect(result).to match(/<email>employee@example.com<\/email>/)
        expect(result).to match(/<label>manager_email<\/label>\s*<value>manager@example.com<\/value>/)
      end
    end
  end
end
