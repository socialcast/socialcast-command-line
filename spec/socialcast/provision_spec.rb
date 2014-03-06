require 'spec_helper'

describe Socialcast::Provision do

  describe ".provision" do
    let!(:credentials) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'credentials.yml')) }
    let!(:ldap_default_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap.yml')) }
    let!(:ldap_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_with_connection_mapping.yml')) }
    let!(:ldap_connection_permission_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_with_connection_permission_mapping.yml')) }
    let!(:ldap_multiple_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_with_multiple_connection_mappings.yml')) }
    let!(:ldap_multiple_connection_permission_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_with_multiple_connection_permission_mappings.yml')) }
    let!(:ldap_with_account_type_without_roles_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_with_account_type_without_roles.yml')) }
    let!(:ldap_connection_permission_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_with_connection_permission_mapping.yml')) }
    let!(:ldap_with_roles_without_account_type_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_with_roles_without_account_type.yml')) }
    let!(:ldap_without_account_type_or_roles_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_without_account_type_or_roles.yml')) }
    let(:result) { '' }
    def create_entry(entry_attributes)
      Net::LDAP::Entry.new("dc=example,dc=com").tap do |e|
        entry_attributes.each_pair do |attr, value|
          e[attr] = value
        end
      end
    end

    before do
      Zlib::GzipWriter.stub(:open).and_yield(result)
      Socialcast.stub(:credentials).and_return(credentials)
      File.stub(:open).with(/users.xml.gz/, anything).and_yield(result)

      RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })
    end
    context "attribute mappings" do
      shared_examples "attributes are mapped properly" do
        it do
          users = Array.wrap(expected_attribute_xml).inject('') do |users_str, user_xml|
            users_str << %Q[<user>
              #{user_xml}
              <custom-fields type="array">
              </custom-fields>
              <account-type>member</account-type>
              <roles type="array">
              </roles>
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

      context "with mappings at the global level" do
        before do
          entry = create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)

          Socialcast::Provision.new(ldap_default_config, {}).provision
        end
        let(:expected_attribute_xml) do
          %Q[<first_name>first name</first_name>
              <last_name>last name</last_name>
              <contact-info>
               <email>user@example.com</email>
              </contact-info>]
        end
        it_behaves_like "attributes are mapped properly"
      end

      context "with mappings at the connection level for one connection" do
        before do
          entry = create_entry :mailCon => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['mailCon', 'isMemberOf'])).and_yield(entry)

          Socialcast::Provision.new(ldap_connection_mapping_config, {}).provision
        end
        let(:expected_attribute_xml) do
          %Q[<contact-info>
               <email>user@example.com</email>
              </contact-info>]
        end
        it_behaves_like "attributes are mapped properly"
      end

      context "with mappings at the connection level for multiple connections" do
        before do
          provision_instance = Socialcast::Provision.new(ldap_multiple_connection_mapping_config, {})

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
              </contact-info>],
          %Q[<first_name>first name2</first_name>
              <contact-info>
               <email>user2@example.com</email>
              </contact-info>]
          ]
        end
        it_behaves_like "attributes are mapped properly"
      end
    end
    context "permission attribute mappings" do
      shared_examples "permission attributes are mapped properly" do
        it do
          users = Array.wrap(expected_permission_xml).inject('') do |users_str, permission_xml|
            users_str << %Q[<user>
              <first_name>first name</first_name>
              <last_name>last name</last_name>
              <contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array">
              </custom-fields>
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

      context "with roles for an external contributor" do
        let(:ldap_groups) { ["cn=External,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"] }
        before do
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
          Socialcast::Provision.new(ldap_default_config, {}).provision
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
          Socialcast::Provision.new(ldap_default_config, {}).provision
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
          Socialcast::Provision.new(ldap_with_account_type_without_roles_config, {}).provision
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
          Socialcast::Provision.new(ldap_with_roles_without_account_type_config, {}).provision
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
          Socialcast::Provision.new(ldap_without_account_type_or_roles_config, {}).provision
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
          Socialcast::Provision.new(ldap_connection_permission_mapping_config, {}).provision
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
          provision_instance = Socialcast::Provision.new(ldap_multiple_connection_permission_mapping_config, {})

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
end
