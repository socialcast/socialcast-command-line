require 'spec_helper'

describe Socialcast::Provision do
  let!(:credentials) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'credentials.yml')) }

  describe ".provision" do
    def create_entry(entry_attributes)
      Net::LDAP::Entry.new("dc=example,dc=com").tap do |e|
        entry_attributes.each_pair do |attr, value|
          e[attr] = value
        end
      end
    end
    context "attribute mappings" do
      let!(:ldap_default_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap.yml')) }
      let!(:ldap_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_with_connection_mapping.yml')) }
      let!(:ldap_multiple_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_with_multiple_connection_mappings.yml')) }
      let(:result) { '' }

      before do
        Zlib::GzipWriter.stub(:open).and_yield(result)
        Socialcast.stub(:credentials).and_return(credentials)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(result)

        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })
      end

      shared_examples "attributes are mapped properly" do
        before do
        end
        it do
          users = user_attributes.inject('') do |users_str, user_attrs|
            users_str << %Q[<user>
              #{user_attrs}
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
        let(:user_attributes) do
          [%Q[<first_name>first name</first_name>
              <last_name>last name</last_name>
              <contact-info>
               <email>user@example.com</email>
              </contact-info>]]
        end
        it_behaves_like "attributes are mapped properly"
      end

      context "with mappings at the connection level for one connection" do
        before do
          entry = create_entry :mailCon => 'user@example.com', :givenName => 'first name', :sn => 'last name'
          Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['mailCon', 'isMemberOf'])).and_yield(entry)

          Socialcast::Provision.new(ldap_connection_mapping_config, {}).provision
        end
        let(:user_attributes) do
          [%Q[<contact-info>
               <email>user@example.com</email>
              </contact-info>]]
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
        let(:user_attributes) do
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
  end
end
