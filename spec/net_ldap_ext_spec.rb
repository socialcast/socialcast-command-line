require 'spec_helper'

describe Net::LDAP::Entry do
  describe '#dereference_mail' do
    context "called on directreport entry" do
      subject {
        entry = Net::LDAP::Entry.new("cn=directreport,dc=example,dc=com")
        entry[:mail] = 'directreport@example.com'
        entry[:manager] = 'cn=bossman,dc=example,dc=com'
        entry
      }
      it "will return bossman email" do
        @manager_entry = Net::LDAP::Entry.new("cn=bossman,dc=example,dc=com")
        @manager_entry[:mail] = 'bossman@example.com'
        ldap = double('net/ldap')
        ldap.should_receive(:search).with(:base => "cn=bossman,dc=example,dc=com", :scope => 0).and_yield(@manager_entry)
        subject.dereference_mail(ldap, 'manager', 'mail').should == "bossman@example.com"
      end
    end
  end
end
