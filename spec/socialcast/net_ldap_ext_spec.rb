require 'spec_helper'

describe Net::LDAP::Entry do
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
    context "attribute passed has a collision between string and Class" do
      subject {
        entry = Net::LDAP::Entry.new("cn=sean,dc=example,dc=com")
        entry[:mail] = 'sean@example.com'
        entry
      }
      before do
        class Mail
          def self.run(entry)
            return "#{entry[:mail].first.gsub(/a/,'b')}"
          end
        end
      end
      after do
        Object.send(:remove_const, :Mail)
      end
      it "returns the result of the Class run method" do
        subject.grab("mail").should == "sebn@exbmple.com"
      end
    end
    context "attribute passed constantizes to a module instead of a class" do
      subject {
        entry = Net::LDAP::Entry.new("cn=sean,dc=example,dc=com")
        entry[:mail] = 'sean@example.com'
        entry
      }
      it "returns the result of the Module run method" do
        module FakeAttributeMap
          def self.run(entry)
            return "#{entry[:mail].first.gsub(/a/,'b')}"
          end
        end
        subject.grab("FakeAttributeMap").should == "sebn@exbmple.com"
      end
    end
  end
end
