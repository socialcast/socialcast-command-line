require 'spec_helper'

describe Socialcast::CommandLine::LDAPConnector do
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
      },
      "group_memberships" => group_membership_mappings
    }
  end
  let(:group_membership_mappings) { nil }

  let(:ldap_config) do
    {
      "connections" => connections,
      "mappings" => mappings,
      "permission_mappings" => permission_mappings,
    }
  end

  let(:ldap) { double(Net::LDAP, :open => nil, :encryption => nil, :auth => nil) }

  before do
    ldap.stub(:open).and_yield
    Net::LDAP.stub(:new).and_return(ldap)
  end

  def create_entry(cn, entry_attributes)
    Net::LDAP::Entry.new("cn=#{cn},dc=example,dc=com").tap do |e|
      entry_attributes.each_pair do |attr, value|
        e[attr] = value
      end
    end
  end

  describe "#each_user_hash" do
    context "when the entry has an email" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry('user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name') }
      before do
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
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

    context("when the entry does not have a unique_identifier or email") do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry('user', :mail => nil, :givenName => 'first name', :sn => 'last name') }
      before do
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
      end
      it 'does not yield the entry' do
        expect do |blk|
          connector.each_user_hash(&blk)
        end.not_to yield_control
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
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry('user', :uid => 'unique identifier', :givenName => 'first name', :sn => 'last name') }
      before do
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'uid', 'isMemberOf'])).and_yield(entry)
      end
      it do
        expect do |blk|
          connector.each_user_hash(&blk)
        end.to yield_with_args(HashWithIndifferentAccess.new({
          'first_name' => 'first name',
          'last_name' => 'last name',
          'unique_identifier' => 'unique identifier',
          'contact_info' => {},
          'custom_fields' => [],
          'account_type' => 'member',
          'roles' => []
        }))
      end
    end

    context "when the entry has a profile photo" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry('user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name') }
      let(:mappings) do
        {
          "first_name" => "givenName",
          "last_name" => "sn",
          "email" => "mail",
          "profile_photo" => "jpegPhoto"
        }
      end
      before do
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
      end
      it "does not retrieve the profile photo data from ldap" do
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

    context "when the entry has a manager" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:employee_entry) { create_entry('user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :manager_dn => 'cn=manager,dc=example,dc=com') }
      let(:manager_entry) { create_entry('manager', :mail => 'manager@example.com', :givenName => 'manager first name', :sn => 'manager last name') }
      let(:employee_mail_entry) { create_entry('user', :mail => 'user@example.com') }
      let(:manager_mail_entry) { create_entry('manager', :mail => 'manager@example.com') }
      let(:mappings) do
        {
          "first_name" => "givenName",
          "last_name" => "sn",
          "email" => "mail",
          "manager" => "manager_dn"
        }
      end
      before do
        ldap.should_receive(:search).once.ordered.with(hash_including(:attributes => ['mail']))
          .and_yield(employee_mail_entry)
          .and_yield(manager_mail_entry)
        ldap.should_receive(:search).once.ordered.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'manager_dn', 'isMemberOf']))
          .and_yield(employee_entry)
          .and_yield(manager_entry)
      end
      it do
        expect do |blk|
          connector.each_user_hash(&blk)
        end.to yield_successive_args(HashWithIndifferentAccess.new({
          'first_name' => 'first name',
          'last_name' => 'last name',
          'contact_info' => {
            'email' => 'user@example.com',
          },
          'custom_fields' => [{
            "id" => "manager_email",
            "label" => "manager_email",
            "value" => "manager@example.com"
          }],
          'account_type' => 'member',
          'roles' => []
        }),
        HashWithIndifferentAccess.new({
          'first_name' => 'manager first name',
          'last_name' => 'manager last name',
          'contact_info' => {
            'email' => 'manager@example.com',
          },
          'custom_fields' => [{
            "id" => "manager_email",
            "label" => "manager_email",
            "value" => nil
          }],

          'account_type' => 'member',
          'roles' => []
        }))
      end
    end

    context "with multiple manager entries" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:employee_entry1) { create_entry('user1', :mail => 'user1@example.com', :givenName => 'first name1', :sn => 'last name1', :manager_dn => 'cn=manager1,dc=example,dc=com') }
      let(:employee_entry2) { create_entry('user2', :mail => 'user2@example.com', :givenName => 'first name2', :sn => 'last name2', :manager_dn => 'cn=manager2,dc=example,dc=com') }
      let(:employee_entry3) { create_entry('user3', :mail => 'user3@example.com', :givenName => 'first name3', :sn => 'last name3', :manager_dn => 'cn=manager1,dc=example,dc=com') }
      let(:employee_mail_entry1) { create_entry('user1', :mail => 'user1@example.com') }
      let(:employee_mail_entry2) { create_entry('user2', :mail => 'user2@example.com') }
      let(:employee_mail_entry3) { create_entry('user3', :mail => 'user3@example.com') }
      let(:manager_entry1) { create_entry('manager1', :mail => 'manager1@example.com', :givenName => 'manager first name1', :sn => 'manager last name1') }
      let(:manager_entry2) { create_entry('manager2', :mail => 'manager2@example.com', :givenName => 'manager first name2', :sn => 'manager last name2') }
      let(:manager_mail_entry1) { create_entry('manager1', :mail => 'manager1@example.com') }
      let(:manager_mail_entry2) { create_entry('manager2', :mail => 'manager2@example.com') }
      let(:mappings) do
        {
          "first_name" => "givenName",
          "last_name" => "sn",
          "email" => "mail",
          "manager" => "manager_dn"
        }
      end
      before do
        ldap.should_receive(:search).once.ordered.with(hash_including(:attributes => ['mail']))
          .and_yield(employee_mail_entry1)
          .and_yield(employee_mail_entry2)
          .and_yield(employee_mail_entry3)
          .and_yield(manager_mail_entry1)
          .and_yield(manager_mail_entry2)

        ldap.should_receive(:search).once.ordered.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'manager_dn', 'isMemberOf']))
          .and_yield(employee_entry1)
          .and_yield(employee_entry2)
          .and_yield(employee_entry3)
          .and_yield(manager_entry1)
          .and_yield(manager_entry2)
      end
      it do
        expect do |blk|
          connector.each_user_hash(&blk)
        end.to yield_successive_args(HashWithIndifferentAccess.new({
            'first_name' => 'first name1',
            'last_name' => 'last name1',
            'contact_info' => {
              'email' => 'user1@example.com',
            },
            'custom_fields' => [{
              "id" => "manager_email",
              "label" => "manager_email",
              "value" => "manager1@example.com"
            }],
            'account_type' => 'member',
            'roles' => []
          }),
          HashWithIndifferentAccess.new({
            'first_name' => 'first name2',
            'last_name' => 'last name2',
            'contact_info' => {
              'email' => 'user2@example.com',
            },
            'custom_fields' => [{
              "id" => "manager_email",
              "label" => "manager_email",
              "value" => "manager2@example.com"
            }],
            'account_type' => 'member',
            'roles' => []
          }),
          HashWithIndifferentAccess.new({
            'first_name' => 'first name3',
            'last_name' => 'last name3',
            'contact_info' => {
              'email' => 'user3@example.com',
            },
            'custom_fields' => [{
              "id" => "manager_email",
              "label" => "manager_email",
              "value" => "manager1@example.com"
            }],
            'account_type' => 'member',
            'roles' => []
          }),
          HashWithIndifferentAccess.new({
            'first_name' => 'manager first name1',
            'last_name' => 'manager last name1',
            'contact_info' => {
              'email' => 'manager1@example.com',
            },
            'custom_fields' => [{
              "id" => "manager_email",
              "label" => "manager_email",
              "value" => nil
            }],
            'account_type' => 'member',
            'roles' => []
          }),
          HashWithIndifferentAccess.new({
            'first_name' => 'manager first name2',
            'last_name' => 'manager last name2',
            'contact_info' => {
              'email' => 'manager2@example.com',
            },
            'custom_fields' => [{
              "id" => "manager_email",
              "label" => "manager_email",
              "value" => nil
            }],
            'account_type' => 'member',
            'roles' => []
          })
        )
      end
    end

    context "with attribute mappings at the connection level" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      before do
        connection.merge!({ "mappings" => { "email" => "mailConnection" } })
        entry = create_entry 'user', :mailConnection => 'user@example.com'
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['mailConnection', 'isMemberOf'])).and_yield(entry)
      end
      it do
        expect do |blk|
          connector.each_user_hash(&blk)
        end.to yield_with_args(HashWithIndifferentAccess.new({
          'contact_info' => {
            'email' => 'user@example.com',
          },
          'custom_fields' => [],
          'account_type' => 'member',
          'roles' => []
        }))
      end
    end
    context "with permission mappings at the connection level" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:ldap_groups) { ["cn=External,dc=example,dc=com", "cn=BizAdmins,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"] }
      before do
        connection.merge!({
          "permission_mappings" => {
            "attribute_name" => "memberOf",
            "account_types" => {
              "external" => "cn=Contractors,dc=example,dc=com"
            },
            "roles" => {
              "tenant_admin" => "cn=Admins,dc=example,dc=com",
              "sbi_admin" => "cn=BizAdmins,dc=example,dc=com",
              "reach_admin" => "cn=BugzillaAdmins,dc=example,dc=com"
            }
          }
        })
        entry = create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name', :memberOf => ldap_groups
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'memberOf'])).and_yield(entry)
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
          'roles' => ['sbi_admin']
        }))
      end
    end
    context "with external ldap group memberships" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) do
        create_entry('user', :mail => 'user@example.com',
          :givenName => 'first name',
          :sn => 'last name',
          :isMemberOf => ["cn=External,dc=example,dc=com", "cn=TownHallAdmins,dc=example,dc=com"])
      end
      before do
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
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
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) do
        create_entry('user', :mail => 'user@example.com',
          :givenName => 'first name',
          :sn => 'last name',
          :isMemberOf => ["cn=TownHallAdmins,dc=example,dc=com", "cn=SbiAdmins,dc=example,dc=com"])
      end
      before do
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'isMemberOf'])).and_yield(entry)
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
    context "with socialcast group ldap group memberships" do
      let(:group_membership_mappings) do
        {
          "filter" => "(objectClass=groupOfUniqueNames)",
          "unique_identifier" => "gid"
        }
      end
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:group_entry1) do
        create_entry('group1', :dn => "cn=Sales,dc=example,dc=com", :gid => "sales_group_id")
      end
      let(:group_entry2) do
        create_entry('group2', :dn => "cn=IT,dc=example,dc=com", :gid => "it_group_id")
      end
      let(:group_entry3) do
        create_entry('group3', :dn => "cn=SFOffice,dc=example,dc=com", :gid => "sf_office_group_id")
      end
      let(:user_entry) do
        create_entry('user', :mail => 'user@example.com',
          :givenName => 'first name',
          :sn => 'last name',
          :isMemberOf => ["cn=SFOffice,dc=example,dc=com", "cn=Sales,dc=example,dc=com"])
      end
      before do
        ldap.should_receive(:search).once.ordered.with(
          :return_result => false,
          :filter => "(objectClass=groupOfUniqueNames)",
          :base => "dc=example,dc=com",
          :attributes => ["gid"]).and_yield(group_entry1).and_yield(group_entry2).and_yield(group_entry3)

        ldap.should_receive(:search).once.ordered.with(
          :return_result => false,
          :filter => "(mail=*)",
          :base => "dc=example,dc=com",
          :attributes => ['givenName', 'sn', 'mail', 'isMemberOf']).and_yield(user_entry)
      end
      it "includes group memberships" do
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
          'roles' => [],
          'groups' => ['sales_group_id', 'sf_office_group_id']
        }))
      end
    end

    context "calling when a search is already being performed" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      before do
        ldap.should_receive(:search).and_yield(create_entry('user', :mail => 'user@example.com'))
      end
      it "raises an error" do
        expect do
          connector.each_user_hash do |user_hash|
            connector.each_user_hash do |another_user_hash|
              # connection already open
            end
          end
        end.to raise_error Socialcast::CommandLine::LDAPConnector::ConcurrentSearchError
      end
    end

    context "calling when a search is already being performed, rescuing, then calling again" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      before do
        ldap.should_receive(:search).and_yield(create_entry('user', :mail => 'user@example.com'))
      end
      it "raises an error" do
        expect do
          connector.each_user_hash do |user_hash|
            begin
              connector.each_user_hash do |another_user_hash|
                # connection already open
              end
            rescue Socialcast::CommandLine::LDAPConnector::ConcurrentSearchError
            end
            connector.each_user_hash do |another_user_hash|
              # connection already open
            end
          end
        end.to raise_error Socialcast::CommandLine::LDAPConnector::ConcurrentSearchError
      end
    end
  end

  describe "#each_photo_hash" do
    context "when the entry has an email and photo" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry('user', :mail => 'user@example.com', :jpegPhoto => "photo") }
      let(:mappings) do
        {
          "first_name" => "givenName",
          "last_name" => "sn",
          "email" => "mail",
          "profile_photo" => "jpegPhoto"
        }
      end
      before do
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['mail', 'jpegPhoto'])).and_yield(entry)
      end
      it do
        expect do |blk|
          connector.each_photo_hash(&blk)
        end.to yield_with_args(HashWithIndifferentAccess.new({
          'email' => 'user@example.com',
          'profile_photo' => "photo"
        }))
      end
    end
    context "when the entry does not have an email" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry('user', :mail => '', :jpegPhoto => "photo") }
      let(:mappings) do
        {
          "first_name" => "givenName",
          "last_name" => "sn",
          "email" => "mail",
          "unique_identifief" => "uid",
          "profile_photo" => "jpegPhoto"
        }
      end
      before do
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['mail', 'jpegPhoto'])).and_yield(entry)
      end
      it 'does not yield' do
        expect do |blk|
          connector.each_photo_hash(&blk)
        end.not_to yield_control
      end
    end

    context "when the entry does not have a photo" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry('user', :mail => 'user@example.com', :jpegPhoto => "") }
      let(:mappings) do
        {
          "first_name" => "givenName",
          "last_name" => "sn",
          "email" => "mail",
          "unique_identifief" => "uid",
          "profile_photo" => "jpegPhoto"
        }
      end
      before do
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['mail', 'jpegPhoto'])).and_yield(entry)
      end
      it 'does not yield' do
        expect do |blk|
          connector.each_photo_hash(&blk)
        end.not_to yield_control
      end
    end

    context "when the entry has a binary photo with incorrect encoding" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry('user', :mail => 'user@example.com', :jpegPhoto => "\x89PNGabc") }
      let(:mappings) do
        {
          "first_name" => "givenName",
          "last_name" => "sn",
          "email" => "mail",
          "profile_photo" => "jpegPhoto"
        }
      end
      before do
        ldap.should_receive(:search).once.with(hash_including(:attributes => ['mail', 'jpegPhoto'])).and_yield(entry)
      end
      it "does not raise an error" do
        expect do |blk|
          connector.each_photo_hash(&blk)
        end.to yield_with_args(HashWithIndifferentAccess.new({
          'email' => 'user@example.com',
          'profile_photo' => "\x89PNGabc"
        }))
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
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry 'user', :uid => 'unique identifier', :givenName => 'first name', :sn => 'last name' }
      before do
        filter = Net::LDAP::Filter.construct('(&(mail=*)(uid=unique identifier))')
        ldap.should_receive(:search).once
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
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name' }
      before do
        filter = Net::LDAP::Filter.construct('(&(mail=*)(mail=user@example.com))')
        ldap.should_receive(:search).once
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
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:entry) { create_entry 'user', :mail => 'user@example.com', :givenName => 'first name', :sn => 'last name' }
      before do
        filter = Net::LDAP::Filter.construct('(&(objectclass=*)(mail=user@example.com))')
        ldap.should_receive(:search).once
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

    context "calling more than once with managers and groups configured" do
      let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
      let(:manager) { create_entry('manager', :mail => 'manager@example.com', :givenName => 'manager first name', :sn => 'manager last name') }
      let(:user1) { create_entry 'user1', :mail => 'user1@example.com', :givenName => 'first name 1', :sn => 'last name 1', :isMemberOf => [] }
      let(:user2) { create_entry 'user2', :mail => 'user2@example.com', :givenName => 'first name 2', :sn => 'last name 2', :isMemberOf => ["cn=Sales,dc=example,dc=com"] }
      let(:group) { create_entry('group', :dn => "cn=Sales,dc=example,dc=com", :gid => "sales_group_id") }
      let(:mappings) do
        {
          "first_name" => "givenName",
          "last_name" => "sn",
          "email" => "mail",
          "manager" => "manager_dn"
        }
      end
      let(:group_membership_mappings) do
        {
          "filter" => "(objectClass=groupOfUniqueNames)",
          "unique_identifier" => "gid"
        }
      end
      before do
        ldap.should_receive(:search).once.ordered.with(
          :return_result => false,
          :filter => "(objectClass=groupOfUniqueNames)",
          :base => "dc=example,dc=com",
          :attributes => ["gid"]).and_yield(group)

        ldap.should_receive(:search).once.ordered.with(
          :return_result => false,
          :filter => "(mail=*)",
          :base => "dc=example,dc=com",
          :attributes => ["mail"]).and_yield(manager)

        filter1 = Net::LDAP::Filter.construct('(&(mail=*)(mail=user1@example.com))')
        ldap.should_receive(:search).once.ordered
          .with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'manager_dn', 'isMemberOf'], :filter => filter1))
          .and_yield(user1)

        filter2 = Net::LDAP::Filter.construct('(&(mail=*)(mail=user2@example.com))')
        ldap.should_receive(:search).once.ordered
          .with(hash_including(:attributes => ['givenName', 'sn', 'mail', 'manager_dn', 'isMemberOf'], :filter => filter2))
          .and_yield(user2)
      end
      it "caches managers and groups" do
        connector.fetch_user_hash('user1@example.com', :identifying_field => 'email').should == {
          'account_type' => 'member',
          'contact_info' => {
            'email' => 'user1@example.com'
          },
          'custom_fields' => [{ 'id' => 'manager_email', 'label' => 'manager_email', 'value' => nil }],
          'first_name' => 'first name 1',
          'last_name' => 'last name 1',
          'groups' => [],
          'roles' => []
        }

        connector.fetch_user_hash('user2@example.com', :identifying_field => 'email').should == {
          'account_type' => 'member',
          'contact_info' => {
            'email' => 'user2@example.com'
          },
          'custom_fields' => [{ 'id' => 'manager_email', 'label' => 'manager_email', 'value' => nil }],
          'first_name' => 'first name 2',
          'last_name' => 'last name 2',
          'groups' => ['sales_group_id'],
          'roles' => []
        }
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
    let(:connector) { Socialcast::CommandLine::LDAPConnector.new('connection_1', ldap_config) }
    let(:entry) do
      Net::LDAP::Entry.new("cn=sean,dc=example,dc=com").tap do |e|
        e[:mail] = 'sean@example.com'
      end
    end
    let(:ldap_instance) { double(Net::LDAP, :encryption => nil, :auth => nil) }
    context "passed hash for attribute" do
      it "returns a string that used defined string template" do
        connector.send(:grab, entry, { "value" => "123%{mail}", "mail" => "mail" }).should == "123sean@example.com"
      end
    end
    context "passed string for attribute" do
      it "returns exact string stored in entry" do
        connector.send(:grab, entry, "mail").should == "sean@example.com"
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
        connector.send(:grab, entry, "Socialcast::CommandLine::FakeAttributeMap").should == "sebn@exbmple.com"
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
        connector.send(:grab, entry, "socialcast/command_line/fake_attribute_map").should == "sebn@exbmple.com"
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
        connector.send(:grab, entry, "mail").should == "sebn@exbmple.com"
      end
    end
    context "attribute passed constantizes to a module instead of a class" do
      it "returns the result of the Module run method" do
        module FakeAttributeMap
          def self.run(entry)
            return "#{entry[:mail].first.gsub(/a/,'b')}"
          end
        end
        connector.send(:grab, entry, "FakeAttributeMap").should == "sebn@exbmple.com"
      end
    end
  end
end
