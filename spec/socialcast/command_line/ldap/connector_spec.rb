require 'spec_helper'

describe Socialcast::CommandLine::LDAP::Connector do
  let!(:ldap_default_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', '..', 'fixtures', 'ldap.yml')) }
  let!(:ldap_with_plugin_mapping_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', '..', 'fixtures', 'ldap_with_plugin_mapping.yml')) }
  let!(:ldap_with_unique_identifier_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', '..', 'fixtures', 'ldap_with_unique_identifier.yml')) }
  let!(:ldap_without_filter_config) { YAML.load_file(File.join(File.dirname(__FILE__), '..', '..', '..', 'fixtures', 'ldap_without_filter.yml')) }

  def create_entry(entry_attributes)
    Net::LDAP::Entry.new("dc=example,dc=com").tap do |e|
      entry_attributes.each_pair do |attr, value|
        e[attr] = value
      end
    end
  end

  describe "#each_user_hash" do
    let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('example_connection_1', ldap_default_config) }
    let(:entry) { create_entry(:mail => 'user@example.com', :givenName => 'first name', :sn => 'last name') }
    before do
      Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
    end
    it do
      expect do |blk|
        connector.each_user_hash(&blk)
      end.to yield_with_args(HashWithIndifferentAccess.new({
        'first_name' => 'first name',
        'last_name' => 'last name',
        'contact_info' => {
          'email' => 'user@example.com',
        },
        'custom_fields' => [],
        'account_type' => 'member',
        'roles' => []
      }))
    end
  end

  describe "#each_ldap_entry" do
    context("when the entry has an email") do
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('example_connection_1', ldap_default_config) }
      let(:entry) { create_entry(:mail => 'user@example.com', :givenName => 'first name', :sn => 'last name') }
      before do
        Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
      end
      it do
        expect do |blk|
          connector.each_ldap_entry(&blk)
        end.to yield_with_args(entry)
      end
    end
    context("when the entry has a unique_identifier") do
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('example_connection_1', ldap_with_unique_identifier_config) }
      let(:entry) { create_entry(:uid => 'unique identifier', :givenName => 'first name', :sn => 'last name') }
      before do
        Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'uid', 'isMemberOf'])).and_yield(entry)
      end
      it do
        expect do |blk|
          connector.each_ldap_entry(&blk)
        end.to yield_with_args(entry)
      end
    end
    context("when the entry does not have a unique_identifier or email") do
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('example_connection_1', ldap_default_config) }
      let(:entry) { create_entry(:mail => nil, :givenName => 'first name', :sn => 'last name') }
      before do
        Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
      end
      it 'does not yield the entry' do
        expect do |blk|
          connector.each_ldap_entry(&blk)
        end.not_to yield_control
      end
    end
  end

  describe "#fetch_user_hash" do
    context "without specifying an identifying field" do
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('example_connection_1', ldap_with_unique_identifier_config) }
      let(:entry) { create_entry :uid => 'unique identifier', :givenName => 'first name', :sn => 'last name' }
      before do
        filter = Net::LDAP::Filter.construct('(&(mail=*)(uid=unique identifier))')
        Net::LDAP.any_instance.should_receive(:search).once
          .with(hash_including(:attributes => ['givenName', 'sn', 'uid', 'isMemberOf'], :filter => filter))
          .and_yield(entry)
      end
      it do
        connector.fetch_user_hash('unique identifier', {}).should == {
          'account_type' => 'member',
          'contact_info' => {},
          'custom_fields' => [],
          'first_name' => 'first name',
          'last_name' => 'last name',
          'roles' => [],
          'unique_identifier' => 'unique identifier'
        }
      end
    end
    context "specifying an identifying field" do
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('example_connection_1', ldap_default_config) }
      let(:entry) { create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name' }
      before do
        filter = Net::LDAP::Filter.construct('(&(mail=*)(mail=user@example.com))')
        Net::LDAP.any_instance.should_receive(:search).once
          .with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'], :filter => filter))
          .and_yield(entry)
      end
      it do
        connector.fetch_user_hash('user@example.com', :identifying_field => 'email').should == {
          'account_type' => 'member',
          'contact_info' => {
            'email' => 'user@example.com'
          },
          'custom_fields' => [],
          'first_name' => 'first name',
          'last_name' => 'last name',
          'roles' => []
        }
      end
    end

    context "without a filter specified" do
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('example_connection_1', ldap_without_filter_config) }
      let(:entry) { create_entry :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name' }
      before do
        filter = Net::LDAP::Filter.construct('(&(objectclass=*)(mail=user@example.com))')
        Net::LDAP.any_instance.should_receive(:search).once
          .with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'], :filter => filter))
          .and_yield(entry)
      end
      it do
        connector.fetch_user_hash('user@example.com', :identifying_field => 'email').should == {
          'account_type' => 'member',
          'contact_info' => {
            'email' => 'user@example.com'
          },
          'custom_fields' => [],
          'first_name' => 'first name',
          'last_name' => 'last name',
          'roles' => []
        }
      end
    end
  end

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