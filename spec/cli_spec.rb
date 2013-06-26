require 'spec_helper'

describe Socialcast::CLI do
  describe '#share' do
    # Expects -u=emily@socialcast.com -p=demo --domain=demo.socialcast.com
    context 'with a basic message' do
      before do
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        stub_request(:post, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/messages.json").
                 with(:body => { "message" => { "body" => "testing", "url" => nil, "message_type" => nil, "attachment_ids" => [], "group_id" => nil }}).
                 with(:headers => {'Accept' => 'application/json'}).
                 to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CLI.start ['share', 'testing']
      end
      it 'should send a POST with a message body of "testing" and nil message-type' do
        # See expectations
      end
    end

    context 'with a message_type message' do
      before do
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        stub_request(:post, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/messages.json").
                 with(:body => /message\_type\"\:review\_request/).
                 with(:body => /please\sreview/).
                 with(:headers => {'Accept' => 'application/json'}).
                 to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CLI.start ['share', 'please review', '--message_type=review_request']
      end
      it 'should send a POST with a message body of "please review" and message_type of "review_request"' do
        # See expectations
      end
    end
    context 'with a group_id param' do
      before do
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        stub_request(:post, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/messages.json").
                 with(:body => /group\_id\"\:123/).
                 with(:headers => {'Accept' => 'application/json'}).
                 to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CLI.start ['share', 'hi', '--group_id=123']
      end
      it 'should send a POST with group_id param == 123' do
        # See expectations
      end
    end
    context "with a proxy" do
      before do
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials_with_proxy.yml')))
        stub_request(:post, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/messages.json").
                 with(:body => /message\_type\"\:null/).
                 with(:body => /testing/).
                 with(:headers => {'Accept' => 'application/json'}).
                 to_return(:status => 200, :body => "", :headers => {})

        Socialcast::CLI.start ['share', 'testing']
      end
      it 'should send a POST with a message body of "testing" and nil message-type' do
        # See expectations
      end
    end

  end

  describe '#provision' do
    before do
      Socialcast::CLI.instance_eval do # to supress warning from stubbing load_configuration
        @no_tasks = true
      end
    end
    context 'with 0 users found in ldap' do
      before do
        Net::LDAP.any_instance.stub(:search).and_return(nil)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with('/my/path/to/ldap.yml').and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.should_receive(:exists?).with('/my/path/to/ldap.yml').and_return(true)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.should_not_receive(:post)
        Kernel.should_receive(:abort).once

        Socialcast::CLI.start ['provision', '-c', '/my/path/to/ldap.yml']
      end
      it 'does not post to Socialcast and throws Kernel.abort' do end # see expectations
    end
    context 'with 0 users found in ldap and force option passed' do
      before do
        Net::LDAP.any_instance.stub(:search).and_return(nil)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with('/my/path/to/ldap.yml').and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.should_receive(:exists?).with('/my/path/to/ldap.yml').and_return(true)

        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.should_receive(:post).once
        Kernel.should_not_receive(:abort)

        Socialcast::CLI.start ['provision', '-c', '/my/path/to/ldap.yml', '-f']
      end
      it 'does post to Socialcast and does not call Kernel.abort' do end # see expectations
    end
    context 'with socialcast returning 401' do
      before do
        Net::LDAP.any_instance.stub(:search).and_return(nil)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with('/my/path/to/ldap.yml').and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.should_receive(:exists?).with('/my/path/to/ldap.yml').and_return(true)

        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        rest_client_resource = double(:rest_client_resource)
        rest_client_resource.stub(:post).and_raise(RestClient::Unauthorized.new(mock('Unauthorized HTTP Response', :code => '401')))
        Socialcast.stub(:resource_for_path).and_return(rest_client_resource)
        Kernel.should_receive(:abort).with("Authenticated user either does not have administration privileges or the community is not configured to allow provisioning. Please contact Socialcast support to if you need help.").once

        Socialcast::CLI.start ['provision', '-c', '/my/path/to/ldap.yml', '-f']
      end
      it "raises Kernel abort" do end # see expectations
    end
    context 'with absolute path to ldap.yml file' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with('/my/path/to/ldap.yml').and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.should_receive(:exists?).with('/my/path/to/ldap.yml').and_return(true)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CLI.start ['provision', '-c', '/my/path/to/ldap.yml']
      end
      it 'resolves absolute path without using current process directory' do end # see expectations
    end
    context 'with plugins option used with non-existent ruby files' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with('/my/path/to/ldap.yml').and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.should_receive(:exists?).with('/my/path/to/ldap.yml').and_return(true)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        RestClient::Resource.any_instance.stub(:post)

      end
      it 'does not post to Socialcast and throws Kernel.abort' do
        lambda { Socialcast::CLI.start ['provision', '-c', '/my/path/to/ldap.yml', '--plugins', ['does_not_exist.rb', 'also_does_not_exist.rb']] }.should raise_error
      end
    end
    context 'with plugins option used with existent ruby file' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with('/my/path/to/ldap.yml').and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.should_receive(:exists?).with('/my/path/to/ldap.yml').and_return(true)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CLI.start ['provision', '-c', '/my/path/to/ldap.yml', '--plugins', [File.join(File.dirname(__FILE__), 'fixtures', 'fake_attribute_map')]]
      end
      it 'successfully processes' do end # see expectations
    end
    context 'with ldap.yml configuration excluding permission_mappings' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'

        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with(/ldap\.yml/).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
      end
      it 'excludes roles element' do
        @result.should_not =~ %r{roles}
      end
    end
    context "with a user marked for termination that shouldn't be and sanity_check option passed" do
      before do
        @entry = Net::LDAP::Entry.new("cn=Ryan,dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @valid_entry = Net::LDAP::Entry.new("cn=Sean,dc=example,dc=com")
        @valid_entry[:mail] = 'sean@example.com'
        ldap_search_block = double("ldapsearchblock")
        ldap_search_block.should_receive(:search).and_yield(@entry)
        ldap_return = double("ldapreturn")
        ldap_return.should_receive(:search).with(include(:filter=>Net::LDAP::Filter.construct("(&(mail=sean@example.com)(mail=*))"))).and_return(@valid_entry)

        Socialcast::CLI.any_instance.should_receive(:create_ldap_instance).and_return(ldap_search_block, ldap_return)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with(/ldap.yml/).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        Socialcast::CLI.any_instance.should_receive(:create_socialcast_user_index_request).and_return(
          double("request1", :get => {"users" => [{"contact_info" => {"email" => @entry[:mail][0]}}]}.to_json),
          double("request2", :get => {"users" => [{"contact_info" => {"email" => @valid_entry[:mail][0]}}]}.to_json),
          double("empty_request", :get => {"users" => []}.to_json)
        )

        RestClient::Resource.any_instance.should_receive(:post).never
      end
      it 'does not post to Socialcast and throws Kernel.abort' do
        lambda { Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml', '--sanity_check', true] }.should raise_error SystemExit
      end
    end
    context 'with external group member' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        @entry[:isMemberOf] = 'cn=External,dc=example,dc=com'

        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with(/ldap.yml/).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
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

        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with(/ldap.yml/).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_with_array_permission_mapping.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
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

        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with(/ldap.yml/).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
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

        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with(/ldap.yml/).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_with_array_permission_mapping.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
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

        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        Socialcast::CLI.any_instance.should_receive(:load_configuration).with(/ldap.yml/).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_with_array_permission_mapping.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
      end
      it 'sets account-type to member' do
        @result.should =~ %r{<account-type>member</account-type>}
      end
      it 'adds sbi_admin role' do
        @result.should =~ %r{<role>sbi_admin</role>}
      end
    end
  end
  context 'with ldap.yml configuration including template value' do
    before do
      @entry = Net::LDAP::Entry.new("dc=example,dc=com")
      @entry[:mail] = 'ryan@example.com'
      @entry[:l] = 'San Francisco'
      @entry[:co] = 'USA'

      Net::LDAP.any_instance.stub(:search).and_yield(@entry)

      @result = ''
      Zlib::GzipWriter.stub(:open).and_yield(@result)
      Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
      Socialcast::CLI.any_instance.should_receive(:load_configuration).with(/ldap.yml/).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_with_interpolated_values.yml')))
      File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

      RestClient::Resource.any_instance.stub(:post)

      Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
    end
    it 'formats l and co according to template' do
      @result.should =~ %r{<location>San Francisco, USA</location>}
    end
  end
  context 'with ldap.yml configuration including manager attribute mapping' do
    before do
      @entry = Net::LDAP::Entry.new("dc=example,dc=com")
      @entry[:mail] = 'ryan@example.com'
      @entry[:manager] = 'cn=bossman,dc=example,dc=com'
      @manager_email = 'bossman@example.com'

      @entry.stub(:dereference_mail).with(kind_of(Net::LDAP), "manager", "mail").and_return(@manager_email)
      Net::LDAP.any_instance.stub(:search).and_yield(@entry)

      @result = ''
      Zlib::GzipWriter.stub(:open).and_yield(@result)
      Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
      Socialcast::CLI.any_instance.should_receive(:load_configuration).with(/ldap.yml/).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_with_manager_attribute.yml')))
      File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)

      RestClient::Resource.any_instance.stub(:post)

      Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
    end
    it 'adds a manager_email entry of bossman@example.com' do
      @result.should =~ /<email>ryan@example.com<\/email>/
      @result.should =~ /<label>manager_email<\/label>\s*<value>bossman@example.com<\/value>/
    end
  end
end
