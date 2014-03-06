require 'spec_helper'

describe Socialcast::Provision do
  let!(:credentials) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'credentials.yml')) }

  describe ".provision" do
    context "attribute mappings" do
      let!(:ldap_default_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap.yml')) }
      let!(:ldap_connection_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap_with_connection_mappings.yml')) }
      let(:result) { '' }
      let(:entry) do
        Net::LDAP::Entry.new("dc=example,dc=com").tap do |e|
          entry_attributes.each_pair do |attr, value|
            e[attr] = value
          end
          e[:mail] = 'user@example.com'
          e[:givenName] = 'first name'
          e[:sn] = 'last name'
        end
      end

      before do
        Zlib::GzipWriter.stub(:open).and_yield(result)
        Socialcast.stub(:credentials).and_return(credentials)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(result)

        RestClient::Resource.any_instance.should_receive(:post).once.with(hash_including(:file => result), { :accept => :json })
      end

      context "with mappings at the global level" do
        let(:entry_attributes) { { :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name' } }
        before do
          Net::LDAP.any_instance.should_receive(:search).with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)

          Socialcast::Provision.new(ldap_default_config, {}).provision
        end
        it "includes the user" do
          result.gsub(/\s/, '').should == %Q[
           <?xml version="1.0" encoding="UTF-8"?>
           <export>
            <users type="array">
             <user>
              <first_name>first name</first_name>
              <last_name>last name</last_name>
              <contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array">
              </custom-fields>
              <account-type>member</account-type>
              <roles type="array">
              </roles>
             </user>
            </users>
           </export>
          ].gsub(/\s/, '')
        end
      end

      context "with mappings at the connection level" do
        let(:entry_attributes) { { :mailCon => 'user@example.com', :givenName => 'first name', :sn => 'last name' } }
        before do
          Net::LDAP.any_instance.should_receive(:search).with(hash_including(:attributes => ['mailCon', 'isMemberOf'])).and_yield(entry)

          Socialcast::Provision.new(ldap_connection_mapping_config, {}).provision
        end
        it "uses the connection mappings instead of the global mappings" do
          result.gsub(/\s/, '').should == %Q[
           <?xml version="1.0" encoding="UTF-8"?>
           <export>
            <users type="array">
             <user>
              <contact-info>
               <email>user@example.com</email>
              </contact-info>
              <custom-fields type="array">
              </custom-fields>
              <account-type>member</account-type>
              <roles type="array">
              </roles>
             </user>
            </users>
           </export>
          ].gsub(/\s/, '')
        end
      end
    end
  end
end
