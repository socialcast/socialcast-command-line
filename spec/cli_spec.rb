require 'spec_helper'

describe Socialcast::CLI do
  describe '#share' do
    
    # Expects -u=emily@socialcast.com -p=demo --domain=demo.socialcast.com
    context 'with a basic message' do
      before do
        stub_request(:post, "https://emily%40socialcast.com:demo@demo.socialcast.com/api/messages.xml").
                 with(:body => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<message>\n  <message-type type=\"yaml\" nil=\"true\"></message-type>\n  <body>testing</body>\n  <url type=\"yaml\" nil=\"true\"></url>\n  <attachment-ids type=\"array\"/>\n</message>\n",
                      :headers => {'Accept'=>'*/*', 'Content-Type'=>'application/xml'}).
                 to_return(:status => 200, :body => "", :headers => {})
        
        Socialcast::CLI.start ['share', 'testing']
      end
      it 'should send a POST with a message body of "testing"' do
        # See expectations
      end
    end
    
    context 'with a message_type message' do
      before do
        stub_request(:post, "https://emily%40socialcast.com:demo@demo.socialcast.com/api/messages.xml").
                 with(:body => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<message>\n  <message-type>review_request</message-type>\n  <body>please review</body>\n  <url type=\"yaml\" nil=\"true\"></url>\n  <attachment-ids type=\"array\"/>\n</message>\n",
                      :headers => {'Accept'=>'*/*', 'Content-Type'=>'application/xml'}).
                 to_return(:status => 200, :body => "", :headers => {})
        
        Socialcast::CLI.start ['share', 'please review', '--message_type=review_request']
      end
      it 'should send a POST with a message body of "please review" and message_type of "review_request"' do
        # See expectations
      end
    end
    
  end
  
  describe '#provision' do
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
end
