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
  describe "#grab" do
    context "passed hash for attribute" do
      subject {
        entry = Net::LDAP::Entry.new("cn=sean,dc=example,dc=com")
        entry[:mail] = 'sean@example.com'
        entry
      }
      it "returns a string that used defined string template" do
        subject.grab({"value" => "123%{mail}", "mail" => "mail"}).should == "123sean@example.com"
      end
    end
    context "passed string for attribute" do
      subject {
        entry = Net::LDAP::Entry.new("cn=sean,dc=example,dc=com")
        entry[:mail] = 'sean@example.com'
        entry
      }
      it "returns exact string stored in entry" do
        subject.grab("mail").should == "sean@example.com"
      end
    end
    context "passed string that can be constantized and the resulting Class responds to run" do
      subject {
        entry = Net::LDAP::Entry.new("cn=sean,dc=example,dc=com")
        entry[:mail] = 'sean@example.com'
        entry
      }
      it "returns result of run method" do
        module Socialcast
          class FakeAttributeMap
            def self.run(entry)
              return "#{entry[:mail].first.gsub(/a/,'b')}"
            end
          end
        end
        subject.grab("Socialcast::FakeAttributeMap").should == "sebn@exbmple.com"
      end
    end
    context "passed string that must be classified and the resulting Class responds to run" do
      subject {
        entry = Net::LDAP::Entry.new("cn=sean,dc=example,dc=com")
        entry[:mail] = 'sean@example.com'
        entry
      }
      it "returns result of run method" do
        module Socialcast
          class FakeAttributeMap
            def self.run(entry)
              return "#{entry[:mail].first.gsub(/a/,'b')}"
            end
          end
        end
        subject.grab("socialcast/fake_attribute_map").should == "sebn@exbmple.com"
      end
    end

  end
end
