require 'spec_helper'

describe Socialcast::CLI do
  describe '#share' do
    # Expects -u=emily@socialcast.com -p=demo --domain=demo.socialcast.com
    context 'with a basic message' do
      before do
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        stub_request(:post, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/messages.json").
                 with(:body => /message\_type\"\:null/).
                 with(:body => /testing/).
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
                 to_return(:status => 200, :body => "", :headers => {})
        
        Socialcast::CLI.start ['share', 'please review', '--message_type=review_request']
      end
      it 'should send a POST with a message body of "please review" and message_type of "review_request"' do
        # See expectations
      end
    end
    context "with a proxy" do
      before do
        Socialcast.stub(:credentials).and_return(YAML.load_file(File.join(File.dirname(__FILE__), 'fixtures', 'credentials_with_proxy.yml')))
        stub_request(:post, "https://ryan%40socialcast.com:foo@test.staging.socialcast.com/api/messages.json").
                 with(:body => /message\_type\"\:null/).
                 with(:body => /testing/).
                 to_return(:status => 200, :body => "", :headers => {})
        
        Socialcast::CLI.start ['share', 'testing']
      end
      it 'should send a POST with a message body of "testing" and nil message-type' do
        # See expectations
      end
    end
    
  end
  
  describe '#provision' do
    context 'with 0 users found in ldap' do
      before do
        Net::LDAP.any_instance.stub(:search).and_return(nil)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        
        File.should_receive(:open).with('/my/path/to/ldap.yml').and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.should_receive(:exists?).with('/my/path/to/ldap.yml').and_return(true)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        File.stub(:open).with(/credentials.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))

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
        
        File.should_receive(:open).with('/my/path/to/ldap.yml').and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.should_receive(:exists?).with('/my/path/to/ldap.yml').and_return(true)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        File.stub(:open).with(/credentials.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))

        RestClient::Resource.any_instance.should_receive(:post).once
        Kernel.should_not_receive(:abort)

        Socialcast::CLI.start ['provision', '-c', '/my/path/to/ldap.yml', '-f']
      end
      it 'does post to Socialcast and does not call Kernel.abort' do end # see expectations
    end
    context 'with absolute path to ldap.yml file' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'
        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)

        File.should_receive(:open).with('/my/path/to/ldap.yml').and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.should_receive(:exists?).with('/my/path/to/ldap.yml').and_return(true)
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        File.stub(:open).with(/credentials.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CLI.start ['provision', '-c', '/my/path/to/ldap.yml']
      end
      it 'resolves absolute path without using current process directory' do end # see expectations
    end
    context 'with ldap.yml configuration excluding permission_mappings' do
      before do
        @entry = Net::LDAP::Entry.new("dc=example,dc=com")
        @entry[:mail] = 'ryan@example.com'

        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        File.stub(:open).with(/ldap.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_without_permission_mappings.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        File.stub(:open).with(/credentials.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))

        RestClient::Resource.any_instance.stub(:post)

        Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
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

        Net::LDAP.any_instance.stub(:search).and_yield(@entry)

        @result = ''
        Zlib::GzipWriter.stub(:open).and_yield(@result)
        File.stub(:open).with(/ldap.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'ldap.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        File.stub(:open).with(/credentials.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))

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
        File.stub(:open).with(/ldap.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_with_array_permission_mapping.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        File.stub(:open).with(/credentials.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))

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
        File.stub(:open).with(/ldap.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'ldap.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        File.stub(:open).with(/credentials.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))

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
        File.stub(:open).with(/ldap.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_with_array_permission_mapping.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        File.stub(:open).with(/credentials.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))

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
        File.stub(:open).with(/ldap.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_with_array_permission_mapping.yml')))
        File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
        File.stub(:open).with(/credentials.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))

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
      File.stub(:open).with(/ldap.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'ldap_with_interpolated_values.yml')))
      File.stub(:open).with(/users.xml.gz/, anything).and_yield(@result)
      File.stub(:open).with(/credentials.yml/).and_yield(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))

      RestClient::Resource.any_instance.stub(:post)

      Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
    end
    it 'formats l and co according to template' do
      @result.should =~ %r{<location>San Francisco, USA</location>}
    end
  end
end
