require 'spec_helper'

describe Socialcast::CommandLine::Provision do
  let!(:credentials) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'credentials.yml')) }
  let!(:ldap_default_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap.yml')) }
  let!(:ldap_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_connection_mapping.yml')) }
  let!(:ldap_connection_permission_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_connection_permission_mapping.yml')) }
  let!(:ldap_multiple_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_multiple_connection_mappings.yml')) }
  let!(:ldap_multiple_connection_permission_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_multiple_connection_permission_mappings.yml')) }
  let!(:ldap_with_account_type_without_roles_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_account_type_without_roles.yml')) }
  let!(:ldap_with_class_ldap_attribute_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_class_ldap_attribute.yml')) }
  let!(:ldap_with_custom_attributes_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_custom_attributes.yml')) }
  let!(:ldap_with_manager_attribute_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_manager_attribute.yml')) }
  let!(:ldap_with_plugin_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_plugin_mapping.yml')) }
  let!(:ldap_with_roles_without_account_type_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_roles_without_account_type.yml')) }
  let!(:ldap_with_unique_identifier_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_unique_identifier.yml')) }
  let!(:ldap_with_profile_photo) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_profile_photo.yml')) }
  let!(:ldap_without_account_type_or_roles_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_without_account_type_or_roles.yml')) }

  def create_entry(entry_attributes)
    Net::LDAP::Entry.new("dc=example,dc=com").tap do |e|
      entry_attributes.each_pair do |attr, value|
        e[attr] = value
      end
    end
  end

  describe "#provision" do
    let(:result) { '' }

    before do
      Zlib::GzipWriter.stub(:open).and_yield(result)
      Socialcast::CommandLine.stub(:credentials).and_return(credentials)
      File.stub(:open).with(/users.xml.gz/, anything).and_yield(result)
    end

    context "when the entry has an email" do
      before do
        entry = create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
        Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })

        Socialcast::CommandLine::Provision.new(ldap_default_config, {}).provision
      end
      it "puts the user in the output file" do
        result.should =~ /user@example.com/
      end
    end
    context "when the entry has a unique_identifier" do
      before do
        entry = create_entry :uid => 'userID', :givenName => 'first name', :sn => 'last name'
        Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'uid', 'isMemberOf'])).and_yield(entry)
        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })

        Socialcast::CommandLine::Provision.new(ldap_with_unique_identifier_config, {}).provision
      end
      it "puts the user in the output file" do
        result.should =~ /userID/
      end
    end
    context "when the entry has no email or unique_identifier" do
      before do
        entry = create_entry :mail => '', :givenName => 'first name', :sn => 'last name'
        Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
        RestClient::Resource.any_instance.should_not_receive(:post)
      end
      it "does not put the user in the output file" do
        expect do
          Socialcast::CommandLine::Provision.new(ldap_default_config, {}).provision
        end.to raise_error(Socialcast::CommandLine::Provision::ProvisionError, "Skipping upload to Socialcast since no users were found")
      end
    end
    context "attribute mappings" do
      shared_examples "attributes are mapped properly" do
        it do
          users = Array.wrap(expected_attribute_xml).inject('') do |users_str, user_xml|
            users_str << %Q[<user>
              #{user_xml}
              <account-type>member</account-type>
              <roles type="array"/>
            </user>]
          end
          result.gsub(/\s/, '').should == %Q[
           <?xml version="1.0" encoding="UTF-8"?>
           <export>
            <users type="array">
            #{users}
            </users>
           </export>
          ].gsub(/\s/, '')
        end
      end

      before do
        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })
      end

      context "with mappings at the global level" do
        before do
          entry = create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)

          Socialcast::CommandLine::Provision.new(ldap_default_config, {}).provision
        end
        let(:expected_attribute_xml) do
          %Q[<first-name>first name</first-name>
              <last-name>last name</last-name>
              <contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array"/>]
        end
        it_behaves_like "attributes are mapped properly"
      end

      context "with mappings at the connection level for one connection" do
        before do
          entry = create_entry :mailCon => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['mailCon', 'isMemberOf'])).and_yield(entry)

          Socialcast::CommandLine::Provision.new(ldap_connection_mapping_config, {}).provision
        end
        let(:expected_attribute_xml) do
          %Q[<contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array"/>]
        end
        it_behaves_like "attributes are mapped properly"
      end

      context "with mappings at the connection level for multiple connections" do
        before do
          provision_instance = Socialcast::CommandLine::Provision.new(ldap_multiple_connection_mapping_config, {})

          ldap_instance1 = double
          provision_instance.should_receive(:create_ldap_instance).once.ordered.and_return(ldap_instance1)
          entry1 = create_entry :mailCon => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          ldap_instance1.should_receive(:search).once.with(hash_including(:attributes => ['mailCon', 'isMemberOf'])).and_yield(entry1)

          ldap_instance2 = double
          provision_instance.should_receive(:create_ldap_instance).once.ordered.and_return(ldap_instance2)
          entry2 = create_entry :mailCon2 => 'user2@example.com', :firstName => 'first name2', :sn => 'last name2'
          ldap_instance2.should_receive(:search).once.with(hash_including(:attributes => ['mailCon2', 'firstName', 'isMemberOf'])).and_yield(entry2)

          provision_instance.provision
        end
        let(:expected_attribute_xml) do
          [%Q[<contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array"/>],
          %Q[<first-name>first name2</first-name>
              <contact-info>
               <email>user2@example.com</email>
              </contact-info>
              <custom-fields type="array"/>]
          ]
        end
        it_behaves_like "attributes are mapped properly"
      end

      context "with custom attribute mappings" do
        before do
          entry = create_entry :mail => 'user@example.com', :custom_ldap1 => 'custom value 1', :custom_ldap2 => 'custom value 2'
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['custom_ldap1', 'custom_ldap2', 'mail', 'isMemberOf'])).and_yield(entry)

          Socialcast::CommandLine::Provision.new(ldap_with_custom_attributes_config, {}).provision
        end
        let(:expected_attribute_xml) do
          %Q[<contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array">
                <custom-field>
                  <id>custom_attr1</id>
                  <label>custom_attr1</label>
                  <value>custom value 1</value>
                </custom-field>
                <custom-field>
                  <id>custom_attr2</id>
                  <label>custom_attr2</label>
                  <value>custom value 2</value>
                </custom-field>
              </custom-fields>]
        end
        it_behaves_like "attributes are mapped properly"
      end

      context "with manager" do
        before do
          provision_instance = Socialcast::CommandLine::Provision.new(ldap_with_manager_attribute_config, {})

          ldap_instance = double
          provision_instance.should_receive(:create_ldap_instance).once.ordered.and_return(ldap_instance)

          user_entry = create_entry :mail => 'user@example.com', :ldap_manager => 'cn=theboss,dc=example,dc=com'
          manager_entry = create_entry :mail => 'boss@example.com'
          ldap_instance.should_receive(:search).once.ordered.with(hash_including(:attributes => ['mail', 'ldap_manager', 'isMemberOf'])).and_yield(user_entry)
          ldap_instance.should_receive(:search).once.ordered.and_yield(manager_entry)

          provision_instance.provision
        end
        let(:expected_attribute_xml) do
          %Q[<contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array">
                <custom-field>
                  <id>manager_email</id>
                  <label>manager_email</label>
                  <value>boss@example.com</value>
                </custom-field>
              </custom-fields>]
        end
        it_behaves_like "attributes are mapped properly"
      end

      context "with an ldap mapping that has the same name as a class" do
        before do
          module TestLdapAttributeMapping end
          entry = create_entry :test_ldap_attribute_mapping => 'user@example.com'
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['test_ldap_attribute_mapping', 'isMemberOf'])).and_yield(entry)

          Socialcast::CommandLine::Provision.new(ldap_with_class_ldap_attribute_config, {}).provision
        end
        after do
          Object.send(:remove_const, :TestLdapAttributeMapping)
        end
        let(:expected_attribute_xml) do
          %Q[<contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array"/>]
        end
        it_behaves_like "attributes are mapped properly"
      end
    end
    context "permission attribute mappings" do
      shared_examples "permission attributes are mapped properly" do
        it do
          users = Array.wrap(expected_permission_xml).inject('') do |users_str, permission_xml|
            users_str << %Q[<user>
              <first-name>first name</first-name>
              <last-name>last name</last-name>
              <contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array"/>
              #{permission_xml}
            </user>]
          end
          result.gsub(/\s/, '').should == %Q[
           <?xml version="1.0" encoding="UTF-8"?>
           <export>
            <users type="array">
            #{users}
            </users>
           </export>
          ].gsub(/\s/, '')
        end
      end

      let(:entry) { create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :isMemberOf => ldap_groups }
      let(:ldap_group_attribute) { 'isMemberOf' }

      before do
        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })
      end

      context "with roles for an external contributor" do
        let(:ldap_groups) { ["cn=External,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"] }
        before do
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
          Socialcast::CommandLine::Provision.new(ldap_default_config, {}).provision
        end
        let(:expected_permission_xml) do
          %Q[<account-type>external</account-type>]
        end
        it_behaves_like "permission attributes are mapped properly"
      end

      context "with roles for a member" do
        let(:ldap_groups) { ["cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"] }
        before do
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
          Socialcast::CommandLine::Provision.new(ldap_default_config, {}).provision
        end
        let(:expected_permission_xml) do
          %Q[<account-type>member</account-type>
              <roles type="array">
                <role>sbi_admin</role>
                <role>town_hall_admin</role>
              </roles>]
        end
        it_behaves_like "permission attributes are mapped properly"
      end

      context "with account_types mapping and no role mappings" do
        let(:ldap_groups) { ["cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"] }
        before do
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
          Socialcast::CommandLine::Provision.new(ldap_with_account_type_without_roles_config, {}).provision
        end
        let(:expected_permission_xml) do
          %Q[<account-type>member</account-type>]
        end
        it_behaves_like "permission attributes are mapped properly"
      end

      context "with role mappings and no account_type mapping" do
        let(:ldap_groups) { ["cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"] }
        before do
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
          Socialcast::CommandLine::Provision.new(ldap_with_roles_without_account_type_config, {}).provision
        end
        let(:expected_permission_xml) do
          %Q[<account-type>member</account-type>
              <roles type="array">
                <role>sbi_admin</role>
                <role>town_hall_admin</role>
              </roles>]
        end
        it_behaves_like "permission attributes are mapped properly"
      end

      context "without account_type or roles mappings" do
        let(:ldap_groups) { ["cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"] }
        before do
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
          Socialcast::CommandLine::Provision.new(ldap_without_account_type_or_roles_config, {}).provision
        end
        let(:expected_permission_xml) do
          %Q[<account-type>member</account-type>]
        end
        it_behaves_like "permission attributes are mapped properly"
      end

      context "with permission mappings at the connection level for one connection" do
        let(:ldap_group_attribute) { 'memberOf' }
        let(:ldap_groups) { ["cn=External,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"] }
        let(:entry) { create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :memberOf => ldap_groups }
        before do
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
          Socialcast::CommandLine::Provision.new(ldap_connection_permission_mapping_config, {}).provision
        end
        let(:expected_permission_xml) do
          %Q[<account-type>member</account-type>
              <roles type="array">
                <role>reach_admin</role>
              </roles>]
        end
        it_behaves_like "permission attributes are mapped properly"
      end

      context "with permission mappings at the connection level for multiple connections" do
        let(:ldap_group_attribute) { 'memberOf' }
        let(:ldap_groups) {  }
        before do
          provision_instance = Socialcast::CommandLine::Provision.new(ldap_multiple_connection_permission_mapping_config, {})

          ldap_instance1 = double
          provision_instance.should_receive(:create_ldap_instance).once.ordered.and_return(ldap_instance1)
          entry1 = create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :memberOf => ["cn=External,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"]
          ldap_instance1.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'memberOf'])).and_yield(entry1)

          ldap_instance2 = double
          provision_instance.should_receive(:create_ldap_instance).once.ordered.and_return(ldap_instance2)
          entry2 = create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :member => ["cn=Contractors,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"]
          ldap_instance2.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'member'])).and_yield(entry2)

          provision_instance.provision
        end
        let(:expected_permission_xml) do
          [%Q[<account-type>member</account-type>
              <roles type="array">
                <role>reach_admin</role>
              </roles>],
           %Q[<account-type>member</account-type>
              <roles type="array">
                <role>sbi_admin</role>
              </roles>]]
        end
        it_behaves_like "permission attributes are mapped properly"
      end
    end
  end

  describe '#dereference_mail' do
    context "called on directreport entry" do
      let(:entry) do
        Net::LDAP::Entry.new("cn=directreport,dc=example,dc=com").tap do |e|
          e[:mail] = 'directreport@example.com'
          e[:manager] = 'cn=bossman,dc=example,dc=com'
        end
      end
      let(:ldap) { double('net/ldap') }
      before do
        manager_entry = Net::LDAP::Entry.new("cn=bossman,dc=example,dc=com")
        manager_entry[:mail] = 'bossman@example.com'
        ldap.should_receive(:search).with(:base => "cn=bossman,dc=example,dc=com", :scope => 0).and_yield(manager_entry)
      end
      it "will return bossman email" do
        Socialcast::CommandLine::Provision.new(ldap_default_config, {}).send(:dereference_mail, entry, ldap, 'manager', 'mail').should == "bossman@example.com"
      end
    end
  end

  describe "#each_user_hash" do
    let(:provision_instance) { Socialcast::CommandLine::Provision.new(ldap_default_config, :plugins => 'socialcast/command_line/fake_attribute_map') }
    before do
      entry = create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
      Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
    end
    it do
      expect do |blk|
        provision_instance.each_user_hash(&blk)
      end.to yield_with_args(HashWithIndifferentAccess.new({
        'first_name' => 'first name',
        'last_name' => 'last name',
        'contact_info' => {
          'email' => 'user@example.com',
        },
        'custom_fields' => [],
        'account_type' => 'member',
        'roles' => []
      }))
    end
  end

  describe "#grab" do
    let(:provision_instance) { Socialcast::CommandLine::Provision.new(ldap_with_plugin_mapping_config, :plugins => 'socialcast/command_line/fake_attribute_map') }
    let(:entry) do
      Net::LDAP::Entry.new("cn=sean,dc=example,dc=com").tap do |e|
        e[:mail] = 'sean@example.com'
      end
    end
    context "passed hash for attribute" do
      it "returns a string that used defined string template" do
        provision_instance.send(:grab, entry, { "value" => "123%{mail}", "mail" => "mail" }).should == "123sean@example.com"
      end
    end
    context "passed string for attribute" do
      it "returns exact string stored in entry" do
        provision_instance.send(:grab, entry, "mail").should == "sean@example.com"
      end
    end
    context "passed string that can be constantized and the resulting Class responds to run" do
      it "returns result of run method" do
        module Socialcast::CommandLine
          class FakeAttributeMap
            def self.run(entry)
              return "#{entry[:mail].first.gsub(/a/,'b')}"
            end
          end
        end
        provision_instance.send(:grab, entry, "Socialcast::CommandLine::FakeAttributeMap").should == "sebn@exbmple.com"
      end
    end
    context "passed string that must be classified and the resulting Class responds to run" do
      it "returns result of run method" do
        module Socialcast::CommandLine
          class FakeAttributeMap
            def self.run(entry)
              return "#{entry[:mail].first.gsub(/a/,'b')}"
            end
          end
        end
        provision_instance.send(:grab, entry, "socialcast/command_line/fake_attribute_map").should == "sebn@exbmple.com"
      end
    end
    context "attribute passed has a collision between string and Class" do
      before do
        class Mail
          def self.run(entry)
            return "#{entry[:mail].first.gsub(/a/,'b')}"
          end
        end
      end
      after do
        Object.send(:remove_const, :Mail)
      end
      it "returns the result of the Class run method" do
        provision_instance.send(:grab, entry, "mail").should == "sebn@exbmple.com"
      end
    end
    context "attribute passed constantizes to a module instead of a class" do
      it "returns the result of the Module run method" do
        module FakeAttributeMap
          def self.run(entry)
            return "#{entry[:mail].first.gsub(/a/,'b')}"
          end
        end
        provision_instance.send(:grab, entry, "FakeAttributeMap").should == "sebn@exbmple.com"
      end
    end
  end

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
    subject { Socialcast::CommandLine::Provision.new(ldap_with_profile_photo, {}).sync_photos }

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
        before { RestClient.should_not_receive(:get) }
        it 'uses the original binary to upload the photo' do; subject; end
      end
      context 'for an image file' do
        let(:photo_data) { "http://socialcast.com/someimage.png" }
        context 'when it successfully downloads' do
          before { RestClient.should_receive(:get).with(photo_data).and_return("\x89PNGabc") }
          it 'downloads the image form the web to upload the photo' do; subject; end
        end
      end
    end

    context 'for when it does not successfully post the photo' do
      context 'for an image file' do
        let(:photo_data) { "http://socialcast.com/someimage.png" }
        before do
          user_search_resource.should_not_receive(:get)
          RestClient.should_receive(:get).with(photo_data).and_raise(RestClient::ResourceNotFound)
        end
        it 'tries to download the image from the web and rescues 404' do; subject; end
      end
    end

  end

end
