require 'spec_helper'

describe Socialcast::CommandLine::LDAP::Connector do
  let(:filter) { "(mail=*)" }
  let(:connection) do
    {
      "username" => "cn=Directory Manager",
      "password" => "a password",
      "host" => "a host",
      "port" => "a port",
      "basedn" => "dc=example,dc=com",
      "filter" => filter
    }
  end
  let(:connections) { { "connection_1" => connection } }

  let(:mappings) do
    {
      "first_name" => "givenName",
      "last_name" => "sn",
      "email" => "mail"
    }
  end
  let(:permission_mappings) do
    {
      "attribute_name" => "isMemberOf",
      "account_types" => {
        "external" => "cn=External,dc=example,dc=com"
      },
      "roles" => {
        "tenant_admin" => "cn=Admins,dc=example,dc=com",
        "sbi_admin" => "cn=SbiAdmins,dc=example,dc=com",
        "reach_admin" => "cn=ReachAdmins,dc=example,dc=com",
        "town_hall_admin" => "cn=TownHallAdmins,dc=example,dc=com"
      }
    }
  end

  let(:ldap_config) do
    {
      "connections" => connections,
      "mappings" => mappings,
      "permission_mappings" => permission_mappings
    }
  end

  def create_entry(entry_attributes)
    Net::LDAP::Entry.new("dc=example,dc=com").tap do |e|
      entry_attributes.each_pair do |attr, value|
        e[attr] = value
      end
    end
  end

  describe "#each_user_hash" do
    context "without ldap group memberships" do
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config) }
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
    context "with external ldap group memberships" do
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config) }
      let(:entry) do
        create_entry(:mail => 'user@example.com',
          :givenName => 'first name',
          :sn => 'last name',
          :isMemberOf => ["cn=External,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"])
      end
      before do
        Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
      end
      it "sets the account_type to 'external' and does not include roles" do
        expect do |blk|
          connector.each_user_hash(&blk)
        end.to yield_with_args(HashWithIndifferentAccess.new({
          'first_name' => 'first name',
          'last_name' => 'last name',
          'contact_info' => {
            'email' => 'user@example.com',
          },
          'custom_fields' => [],
          'account_type' => 'external'
        }))
      end
    end
    context "with role ldap group memberships" do
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config) }
      let(:entry) do
        create_entry(:mail => 'user@example.com',
          :givenName => 'first name',
          :sn => 'last name',
          :isMemberOf => ["cn=TownHallAdmins,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com"])
      end
      before do
        Net::LDAP.any_instance.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
      end
      it "sets the account_type to 'member' and includes roles" do
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
          'roles' => ['sbi_admin', 'town_hall_admin']
        }))
      end
    end
  end

  describe "#each_ldap_entry" do
    context("when the entry has an email") do
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config) }
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
      let(:mappings) do
        {
          "first_name" => "givenName",
          "last_name" => "sn",
          "unique_identifier" => "uid"
        }
      end
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config) }
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
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config) }
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
      let(:mappings) do
        {
          "first_name" => "givenName",
          "last_name" => "sn",
          "unique_identifier" => "uid"
        }
      end
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config) }
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
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config) }
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
      let(:filter) { "" }
      let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config) }
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
        Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config).send(:dereference_mail, entry, 'manager', 'mail').should == "bossman@example.com"
      end
    end
  end

  describe "#grab" do
    let(:mappings) do
      {
        "first_name" => "socialcast/command_line/fake_attribute_map",
        "last_name" => "sn",
        "email" => "mail"
      }
    end
    let(:connector) { Socialcast::CommandLine::LDAP::Connector.new('connection_1', ldap_config) }
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
