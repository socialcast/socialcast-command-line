require 'spec_helper'

describe Socialcast::CommandLine::ProvisionUser do
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
  let!(:ldap_without_account_type_or_roles_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'ldap_without_account_type_or_roles.yml')) }

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

        Socialcast::CommandLine::ProvisionUser.new(ldap_default_config, {}).provision
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

        Socialcast::CommandLine::ProvisionUser.new(ldap_with_unique_identifier_config, {}).provision
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
          Socialcast::CommandLine::ProvisionUser.new(ldap_default_config, {}).provision
        end.to raise_error(Socialcast::CommandLine::ProvisionUser::ProvisionError, "Skipping upload to Socialcast since no users were found")
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

          Socialcast::CommandLine::ProvisionUser.new(ldap_default_config, {}).provision
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
          provision_instance = Socialcast::CommandLine::ProvisionUser.new(ldap_multiple_connection_mapping_config, {})

          ldap_instance1 = double(Net::LDAP, :encryption => nil, :auth => nil)
          Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance1)
          entry1 = create_entry :mailCon => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          ldap_instance1.should_receive(:search).once.with(hash_including(:attributes => ['mailCon', 'isMemberOf'])).and_yield(entry1)

          ldap_instance2 = double(Net::LDAP, :encryption => nil, :auth => nil)
          Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance2)
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

          Socialcast::CommandLine::ProvisionUser.new(ldap_with_custom_attributes_config, {}).provision
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
          provision_instance = Socialcast::CommandLine::ProvisionUser.new(ldap_with_manager_attribute_config, {})

          ldap_instance = double(Net::LDAP, :encryption => nil, :auth => nil)
          Net::LDAP.should_receive(:new).once.and_return(ldap_instance)

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

          Socialcast::CommandLine::ProvisionUser.new(ldap_with_class_ldap_attribute_config, {}).provision
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
          Socialcast::CommandLine::ProvisionUser.new(ldap_default_config, {}).provision
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
          Socialcast::CommandLine::ProvisionUser.new(ldap_default_config, {}).provision
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
          Socialcast::CommandLine::ProvisionUser.new(ldap_with_account_type_without_roles_config, {}).provision
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
          Socialcast::CommandLine::ProvisionUser.new(ldap_with_roles_without_account_type_config, {}).provision
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
          Socialcast::CommandLine::ProvisionUser.new(ldap_without_account_type_or_roles_config, {}).provision
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
          provision_instance = Socialcast::CommandLine::ProvisionUser.new(ldap_multiple_connection_permission_mapping_config, {})

          ldap_instance1 = double(Net::LDAP, :encryption => nil, :auth => nil)
          Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance1)
          entry1 = create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :memberOf => ["cn=External,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"]
          ldap_instance1.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'memberOf'])).and_yield(entry1)

          ldap_instance2 = double(Net::LDAP, :encryption => nil, :auth => nil)
          Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance2)
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

    context "with no basedn configured" do
      before do
        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })

        provision_instance = Socialcast::CommandLine::ProvisionUser.new(ldap_blank_basedn_config, {})

        root_entry = create_entry(:namingcontexts => ['dc=foo,dc=com', 'dc=bar,dc=com'])
        ldap_instance = double(Net::LDAP, :encryption => nil, :auth => nil)
        ldap_instance.should_receive(:search_root_dse).once.and_return(root_entry)
        Net::LDAP.should_receive(:new).once.and_return(ldap_instance)

        user_entry = create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name'
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
    let(:provision_instance) { Socialcast::CommandLine::ProvisionUser.new(ldap_default_config) }
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

  describe "#fetch_user_hash" do
    context "when the first connector returns the entry" do
      let(:provision_instance) { Socialcast::CommandLine::ProvisionUser.new(ldap_multiple_connection_mapping_config, {}) }
      let(:entry) { create_entry :mailCon => 'user@example.com' }
      before do
        filter = Net::LDAP::Filter.construct('(&(mail=*)(mailCon=user@example.com))')
        Net::LDAP.any_instance.should_receive(:search).once
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
      let(:provision_instance) { Socialcast::CommandLine::ProvisionUser.new(ldap_multiple_connection_mapping_config, {}) }
      let(:entry) { create_entry :mailCon2 => 'user@example.com', :firstName => 'first name' }
      before do
        ldap_instance1 = double(Net::LDAP, :auth => nil)
        Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance1)
        filter1 = Net::LDAP::Filter.construct('(&(mail=*)(mailCon=user@example.com))')
        ldap_instance1.should_receive(:search).once.ordered
          .with(hash_including(:attributes => ['mailCon', 'isMemberOf'], :filter => filter1))

        ldap_instance2 = double(Net::LDAP, :auth => nil)
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
      let(:provision_instance) { Socialcast::CommandLine::ProvisionUser.new(ldap_multiple_connection_mapping_config, {}) }
      before do
        ldap_instance1 = double(Net::LDAP, :auth => nil)
        Net::LDAP.should_receive(:new).once.ordered.and_return(ldap_instance1)
        filter1 = Net::LDAP::Filter.construct('(&(mail=*)(mailCon=user@example.com))')
        ldap_instance1.should_receive(:search)
          .with(hash_including(:attributes => ['mailCon', 'isMemberOf'], :filter => filter1))

        ldap_instance2 = double(Net::LDAP, :auth => nil)
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
end
