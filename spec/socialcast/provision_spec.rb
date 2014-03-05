require 'spec_helper'

describe Socialcast::Provision do
  let!(:credentials) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'credentials.yml')) }

  describe ".provision" do
    let!(:ldap_default_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', 'fixtures', 'ldap.yml')) }

    context "when a user is found" do
      let(:result) { '' }
      before do
        entry = Net::LDAP::Entry.new("dc=example,dc=com")
        entry[:mail] = 'user@example.com'

        Net::LDAP.any_instance.stub(:search).and_yield(entry)

        Zlib::GzipWriter.stub(:open).and_yield(result)
        Socialcast.stub(:credentials).and_return(credentials)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(result)

        RestClient::Resource.any_instance.should_receive(:post).with(hash_including(:file => result), { :accept => :json })

        Socialcast::Provision.provision(ldap_default_config, {})
      end
      it "includes the user" do
        result.gsub(/\s/, '').should == %Q[
         <?xml version="1.0" encoding="UTF-8"?>
         <export>
          <users type="array">
           <user>
            <first_name/>
            <last_name/>
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
