require 'spec_helper'

describe Socialcast::CommandLine::Provision do
  let!(:credentials) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'credentials.yml')) }
  let!(:ldap_default_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap.yml')) }
  let!(:ldap_blank_basedn_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_blank_basedn.yml')) }
  let!(:ldap_connection_permission_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_connection_permission_mapping.yml')) }
  let!(:ldap_multiple_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_multiple_connection_mappings.yml')) }
  let!(:ldap_multiple_connection_permission_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_multiple_connection_permission_mappings.yml')) }
  let!(:ldap_with_account_type_without_roles_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_account_type_without_roles.yml')) }
  let!(:ldap_with_class_ldap_attribute_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_class_ldap_attribute.yml')) }
  let!(:ldap_with_custom_attributes_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_custom_attributes.yml')) }
  let!(:ldap_with_manager_attribute_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_manager_attribute.yml')) }
  let!(:ldap_with_roles_without_account_type_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_roles_without_account_type.yml')) }
  let!(:ldap_with_unique_identifier_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_unique_identifier.yml')) }
  let!(:ldap_with_profile_photo_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_with_profile_photo.yml')) }
  let!(:ldap_without_account_type_or_roles_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_without_account_type_or_roles.yml')) }
  let!(:ldap_without_options_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_without_options.yml')) }

  let(:binary_photo_data) { "\x89PNGabc".force_encoding('binary') }
  def create_entry(cn, entry_attributes)
    Net::LDAP::Entry.new("cn=#{cn},dc=example,dc=com").tap do |e|
      entry_attributes.each_pair do |attr, value|
        e[attr] = value
      end
    end
  end

  let(:ldap) do
    ldap_instance = double(Net::LDAP, :auth => nil, :encryption => nil)
    ldap_instance.should_receive(:open).and_yield(ldap_instance)
    Net::LDAP.should_receive(:new).and_return(ldap_instance)
    ldap_instance
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
        entry = create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })

        Socialcast::CommandLine::Provision.new(ldap_default_config, {}).provision
      end
      it "puts the user in the output file" do
        result.should =~ /user@example.com/
      end
    end
    context "when the entry has a unique_identifier" do
      before do
        entry = create_entry 'user', :uid => 'userID', :givenName => 'first name', :sn => 'last name'
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'uid', 'isMemberOf'])).and_yield(entry)
        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })

        Socialcast::CommandLine::Provision.new(ldap_with_unique_identifier_config, {}).provision
      end
      it "puts the user in the output file" do
        result.should =~ /userID/
      end
    end
    context "when the entry has no email or unique_identifier" do
      before do
        entry = create_entry 'user', :mail => '', :givenName => 'first name', :sn => 'last name'
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
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
          entry = create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)

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

      context "with mappings at the connection level" do
        before do
          provision_instance = Socialcast::CommandLine::Provision.new(ldap_multiple_connection_mapping_config, {})

          ldap_instance1 = double(Net::LDAP, :encryption => nil, :auth => nil)
          ldap_instance1.should_receive(:open).and_yield(ldap_instance1)
          Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance1)
          entry1 = create_entry 'user', :mailCon => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          ldap_instance1.should_receive(:search).once.with(hash_including(:attributes => ['mailCon', 'isMemberOf'])).and_yield(entry1)

          ldap_instance2 = double(Net::LDAP, :encryption => nil, :auth => nil)
          ldap_instance2.should_receive(:open).and_yield(ldap_instance2)
          Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance2)
          entry2 = create_entry 'user', :mailCon2 => 'user2@example.com', :firstName => 'first name2', :sn => 'last name2'
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
          entry = create_entry 'user', :mail => 'user@example.com', :custom_ldap1 => 'custom value 1', :custom_ldap2 => 'custom value 2'
          ldap.should_receive(:search).once.with(hash_including(:attributes => ['custom_ldap1', 'custom_ldap2', 'mail', 'isMemberOf'])).and_yield(entry)

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

          ldap_instance = double(Net::LDAP, :encryption => nil, :auth => nil)
          ldap_instance.should_receive(:open).and_yield(ldap_instance)
          Net::LDAP.should_receive(:new).once.and_return(ldap_instance)

          user_entry = create_entry 'user', :mail => 'user@example.com', :ldap_manager => 'cn=theboss,dc=example,dc=com'
          manager_entry = create_entry 'theboss', :mail => 'boss@example.com'
          ldap_instance.should_receive(:search).once.ordered.and_yield(user_entry).and_yield(manager_entry)
          ldap_instance.should_receive(:search).once.ordered.and_yield(user_entry).and_yield(manager_entry)

          provision_instance.provision
        end
        let(:expected_attribute_xml) do
          [%Q[<contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array">
                <custom-field>
                  <id>manager_email</id>
                  <label>manager_email</label>
                  <value>boss@example.com</value>
                </custom-field>
              </custom-fields>],
          %Q[<contact-info>
               <email>boss@example.com</email>
              </contact-info>
              <custom-fields type="array">
                <custom-field>
                  <id>manager_email</id>
                  <label>manager_email</label>
                  <value nil="true"/>
                </custom-field>
              </custom-fields>]]
        end
        it_behaves_like "attributes are mapped properly"
      end

      context "with an ldap mapping that has the same name as a class" do
        before do
          module TestLdapAttributeMapping end
          entry = create_entry 'user', :test_ldap_attribute_mapping => 'user@example.com'
          ldap.should_receive(:search).once.with(hash_including(:attributes => ['test_ldap_attribute_mapping', 'isMemberOf'])).and_yield(entry)

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

      context "without options specified" do
        before do
          entry = create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)

          Socialcast::CommandLine::Provision.new(ldap_without_options_config, {}).provision
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

      context "with profile_photo attribute mappings" do
        before do
          entry = create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'memberof'])).and_yield(entry)

          Socialcast::CommandLine::Provision.new(ldap_with_profile_photo_config, {}).provision
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

      let(:entry) { create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :isMemberOf => ldap_groups }
      let(:ldap_group_attribute) { 'isMemberOf' }

      before do
        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })
      end

      context "with roles for an external contributor" do
        let(:ldap_groups) { ["cn=External,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"] }
        before do
          ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
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
          ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
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
          ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
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
          ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
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
          ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', ldap_group_attribute])).and_yield(entry)
          Socialcast::CommandLine::Provision.new(ldap_without_account_type_or_roles_config, {}).provision
        end
        let(:expected_permission_xml) do
          %Q[<account-type>member</account-type>]
        end
        it_behaves_like "permission attributes are mapped properly"
      end

      context "with permission mappings at the connection level" do
        let(:ldap_group_attribute) { 'memberOf' }
        let(:ldap_groups) {  }
        before do
          provision_instance = Socialcast::CommandLine::Provision.new(ldap_multiple_connection_permission_mapping_config, {})

          ldap_instance1 = double(Net::LDAP, :encryption => nil, :auth => nil)
          ldap_instance1.should_receive(:open).and_yield(ldap_instance1)
          Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance1)
          entry1 = create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :memberOf => ["cn=External,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"]
          ldap_instance1.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'memberOf'])).and_yield(entry1)

          ldap_instance2 = double(Net::LDAP, :encryption => nil, :auth => nil)
          ldap_instance2.should_receive(:open).and_yield(ldap_instance2)
          Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance2)
          entry2 = create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :member => ["cn=Contractors,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"]
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

    context "with no basedn configured" do
      before do
        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })

        provision_instance = Socialcast::CommandLine::Provision.new(ldap_blank_basedn_config, {})

        root_entry = create_entry('domain', :namingcontexts => ['dc=foo,dc=com', 'dc=bar,dc=com'])
        ldap_instance = double(Net::LDAP, :encryption => nil, :auth => nil)
        ldap_instance.should_receive(:search_root_dse).once.and_return(root_entry)
        ldap_instance.should_receive(:open).and_yield(ldap_instance)
        Net::LDAP.should_receive(:new).once.and_return(ldap_instance)

        user_entry = create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
        ldap_instance.should_receive(:search).once.ordered.with(hash_including(:base => 'dc=foo,dc=com', :attributes => ['givenName', 'sn', 'mail', 'isMemberOf']))
        ldap_instance.should_receive(:search).once.ordered.with(hash_including(:base => 'dc=bar,dc=com', :attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(user_entry)

        provision_instance.provision
      end
      it "searches all basedns and puts the user in the output file" do
        result.should =~ /user@example.com/
      end
    end
  end

  describe "#each_user_hash" do
    let(:provision_instance) { Socialcast::CommandLine::Provision.new(ldap_default_config) }
    before do
      entry = create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
      ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
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

  describe "#fetch_user_hash" do
    context "when the first connector returns the entry" do
      let(:provision_instance) { Socialcast::CommandLine::Provision.new(ldap_multiple_connection_mapping_config, {}) }
      let(:entry) { create_entry 'user', :mailCon => 'user@example.com' }
      before do
        filter = Net::LDAP::Filter.construct('(&(mail=*)(mailCon=user@example.com))')
        ldap.should_receive(:search).once
          .with(hash_including(:attributes => ['mailCon', 'isMemberOf'], :filter => filter))
          .and_yield(entry)
      end
      it "returns the entry" do
        provision_instance.fetch_user_hash('user@example.com', :identifying_field => 'email').should == {
          'account_type' => 'member',
          'contact_info' => {
            'email' => 'user@example.com'
          },
          'custom_fields' => [],
          'roles' => []
        }
      end
    end
    context "when another connector returns the entry" do
      let(:provision_instance) { Socialcast::CommandLine::Provision.new(ldap_multiple_connection_mapping_config, {}) }
      let(:entry) { create_entry 'user', :mailCon2 => 'user@example.com', :firstName => 'first name' }
      before do
        ldap_instance1 = double(Net::LDAP, :auth => nil)
        ldap_instance1.should_receive(:open).and_yield(ldap_instance1)
        Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance1)
        filter1 = Net::LDAP::Filter.construct('(&(mail=*)(mailCon=user@example.com))')
        ldap_instance1.should_receive(:search).once.ordered
          .with(hash_including(:attributes => ['mailCon', 'isMemberOf'], :filter => filter1))

        ldap_instance2 = double(Net::LDAP, :auth => nil)
        ldap_instance2.should_receive(:open).and_yield(ldap_instance2)
        Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance2)
        filter2 = Net::LDAP::Filter.construct('(&(mail=*)(mailCon2=user@example.com))')
        ldap_instance2.should_receive(:search).once.ordered
          .with(hash_including(:attributes => ['mailCon2', 'firstName', 'isMemberOf'], :filter => filter2))
          .and_yield(entry)

      end
      it "returns the entry" do
        provision_instance.fetch_user_hash('user@example.com', :identifying_field => 'email').should == {
          'account_type' => 'member',
          'contact_info' => {
            'email' => 'user@example.com'
          },
          'first_name' => 'first name',
          'custom_fields' => [],
          'roles' => []
        }
      end
    end
    context "when no connectors return the entry" do
      let(:provision_instance) { Socialcast::CommandLine::Provision.new(ldap_multiple_connection_mapping_config, {}) }
      before do
        ldap_instance1 = double(Net::LDAP, :auth => nil)
        ldap_instance1.should_receive(:open).and_yield(ldap_instance1)
        Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance1)
        filter1 = Net::LDAP::Filter.construct('(&(mail=*)(mailCon=user@example.com))')
        ldap_instance1.should_receive(:search)
          .with(hash_including(:attributes => ['mailCon', 'isMemberOf'], :filter => filter1))

        ldap_instance2 = double(Net::LDAP, :auth => nil)
        ldap_instance2.should_receive(:open).and_yield(ldap_instance2)
        Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance2)
        filter2 = Net::LDAP::Filter.construct('(&(mail=*)(mailCon2=user@example.com))')
        ldap_instance2.should_receive(:search).once.ordered
          .with(hash_including(:attributes => ['mailCon2', 'firstName', 'isMemberOf'], :filter => filter2))
      end
      it "returns nil" do
        provision_instance.fetch_user_hash('user@example.com', :identifying_field => 'email').should be_nil
      end
    end
  end

  describe '#sync_photos' do
    context 'with a single ldap connection' do
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
        entry = create_entry 'user', :mail => 'user@example.com', :jpegPhoto => photo_data
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['mail', 'jpegPhoto'])).and_yield(entry)

        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)
      end
      let(:sync_photos) { Socialcast::CommandLine::Provision.new(ldap_with_profile_photo_config, {}).sync_photos }

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
          let(:photo_data) { binary_photo_data }
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
              RestClient.should_receive(:get).with(photo_data).and_return(binary_photo_data)
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
            user_search_resource.should_not_receive(:get)
            RestClient.should_receive(:get).with(photo_data).and_raise(RestClient::ResourceNotFound)
            sync_photos
          end
          it 'tries to download the image from the web and rescues 404' do end
        end
      end
    end

    context 'with multiple ldap connections' do
      let(:user_search_resource) { double(:user_search_resource) }
      let(:search_api_response1) do
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
      let(:search_api_response2) do
        {
          'users' => [
            {
              'id' => 8,
              'avatars' => {
                'is_system_default' => true
              }
            }
          ]
        }
      end

      let(:sync_photos) { Socialcast::CommandLine::Provision.new(ldap_multiple_connection_mapping_config, {}).sync_photos }
      before do
        ldap_instance1 = double(Net::LDAP, :encryption => nil, :auth => nil)
        ldap_instance1.should_receive(:open).and_yield(ldap_instance1)
        Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance1)
        entry1 = create_entry 'user', :mailCon => 'user@example.com', :photoCon => binary_photo_data
        ldap_instance1.should_receive(:search).once.with(hash_including(:attributes => ['mailCon', 'photoCon'])).and_yield(entry1)

        ldap_instance2 = double(Net::LDAP, :encryption => nil, :auth => nil)
        ldap_instance2.should_receive(:open).and_yield(ldap_instance2)
        Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance2)
        entry2 = create_entry 'user', :mailCon2 => 'user2@example.com', :photoCon2 => binary_photo_data
        ldap_instance2.should_receive(:search).once.with(hash_including(:attributes => ['mailCon2', 'photoCon2'])).and_yield(entry2)

        Socialcast::CommandLine.stub(:resource_for_path).with('/api/users/search', anything).and_return(user_search_resource)

        user_search_resource.should_receive(:get).once.and_return(search_api_response1.to_json)
        user_search_resource.should_receive(:get).once.and_return(search_api_response2.to_json)

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
end
