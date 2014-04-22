require 'spec_helper'

describe Socialcast::CommandLine::LDAP::Connector do
  let!(:ldap_default_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', '..', 'fixtures', 'ldap.yml')) }
  let!(:ldap_with_plugin_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', '..', 'fixtures', 'ldap_with_plugin_mapping.yml')) }

  describe '#dereference_mail' do
    context "called on directreport entry" do
      let(:entry) do
        Net::LDAP::Entry.new("cn=directreport,dc=example,dc=com").tap do |e|
          e[:mail] = 'directreport@example.com'
          e[:manager] = 'cn=bossman,dc=example,dc=com'
        end
      end
      let(:ldap) { double(Net::LDAP, :encryption => nil, :auth => nil) }
      before do
        Net::LDAP.should_receive(:new).and_return(ldap)
        manager_entry = Net::LDAP::Entry.new("cn=bossman,dc=example,dc=com")
        manager_entry[:mail] = 'bossman@example.com'
        ldap.should_receive(:search).with(:base => "cn=bossman,dc=example,dc=com", :scope => 0).and_yield(manager_entry)
      end
      it "will return bossman email" do
        Socialcast::CommandLine::LDAP::Connector.new('example_connection_1', ldap_default_config).send(:dereference_mail, entry, 'manager', 'mail').should == "bossman@example.com"
      end
    end
  end

  describe "#grab" do
    let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('example_connection_1', ldap_with_plugin_mapping_config) }
    let(:entry) do
      Net::LDAP::Entry.new("cn=sean,dc=example,dc=com").tap do |e|
        e[:mail] = 'sean@example.com'
      end
    end
    let(:ldap_instance) { double(Net::LDAP, :encryption => nil, :auth => nil) }
    context "passed hash for attribute" do
      it "returns a string that used defined string template" do
        connector.grab(entry, { "value" => "123%{mail}", "mail" => "mail" }).should == "123sean@example.com"
      end
    end
    context "passed string for attribute" do
      it "returns exact string stored in entry" do
        connector.grab(entry, "mail").should == "sean@example.com"
      end
    end
    context "passed string that can be constantized and the resulting Class responds to run" do
      it "returns result of run method" do
        module Socialcast::CommandLine
          class FakeAttributeMap
            def self.run(entry)
              return "#{entry[:mail].first.gsub(/a/,'b')}"
            end
          end
        end
        connector.grab(entry, "Socialcast::CommandLine::FakeAttributeMap").should == "sebn@exbmple.com"
      end
    end
    context "passed string that must be classified and the resulting Class responds to run" do
      it "returns result of run method" do
        module Socialcast::CommandLine
          class FakeAttributeMap
            def self.run(entry)
              return "#{entry[:mail].first.gsub(/a/,'b')}"
            end
          end
        end
        connector.grab(entry, "socialcast/command_line/fake_attribute_map").should == "sebn@exbmple.com"
      end
    end
    context "attribute passed has a collision between string and Class" do
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
        connector.grab(entry, "mail").should == "sebn@exbmple.com"
      end
    end
    context "attribute passed constantizes to a module instead of a class" do
      it "returns the result of the Module run method" do
        module FakeAttributeMap
          def self.run(entry)
            return "#{entry[:mail].first.gsub(/a/,'b')}"
          end
        end
        connector.grab(entry, "FakeAttributeMap").should == "sebn@exbmple.com"
      end
    end
  end
end
