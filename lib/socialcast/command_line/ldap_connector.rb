require 'net/ldap'
require 'active_support/core_ext/object/blank'
require 'active_support/core_ext/array/wrap'

module Socialcast
  module CommandLine
    class LDAPConnector
      UNIQUE_IDENTIFIER = "unique_identifier"
      EMAIL = "email"
      PRIMARY_ATTRIBUTES = [UNIQUE_IDENTIFIER, 'first_name', 'last_name', 'employee_number']
      CONTACT_ATTRIBUTES = [EMAIL, 'location', 'cell_phone', 'office_phone']
      PROFILE_PHOTO_ATTRIBUTE = 'profile_photo'

      attr_reader :attribute_mappings, :connection_name

      def self.with_connector(connection_name, config)
        connection_config = config["connections"][connection_name]
        ldap = Net::LDAP.new(:host => connection_config["host"], :port => connection_config["port"], :base => connection_config["basedn"]).tap do |ldap_instance|
          ldap_instance.encryption connection_config['encryption'].to_sym if connection_config['encryption']
          ldap_instance.auth connection_config["username"], connection_config["password"]
        end

        ldap.open do |connected_ldap_instance|
          yield new(connection_name, config, connected_ldap_instance)
        end
      end

      def self.attribute_mappings_for(connection_name, config)
        config['connections'][connection_name]['mappings'] || config.fetch('mappings', {})
      end

      def initialize(connection_name, config, ldap)
        @connection_name = connection_name
        @config = config
        @ldap = ldap
      end

      def each_user_hash
        each_ldap_entry(ldap_user_search_attributes) do |entry|
          yield build_user_hash_from_mappings(entry)
        end
      end

      def each_photo_hash
        each_ldap_entry(ldap_photo_search_attributes) do |entry|
          photo_hash = build_photo_hash_from_mappings(entry)
          yield photo_hash if photo_hash.present?
        end
      end

      def fetch_user_hash(identifier, options)
        options = options.dup
        identifying_field = options.delete(:identifying_field) || UNIQUE_IDENTIFIER

        filter = if connection_config['filter'].present?
                   Net::LDAP::Filter.construct(connection_config['filter'])
                 else
                   Net::LDAP::Filter.pres("objectclass")
                 end

        filter = filter & Net::LDAP::Filter.construct("#{attribute_mappings[identifying_field]}=#{identifier}")

        search(:base => connection_config['basedn'], :filter => filter, :attributes => ldap_user_search_attributes, :size => 1) do |entry|
          return build_user_hash_from_mappings(entry)
        end

        nil
      end

      def attribute_mappings
        @attribute_mappings ||= LDAPConnector.attribute_mappings_for(@connection_name, @config)
      end

      # grab a *single* value of an attribute
      # abstracts away ldap multivalue attributes
      def grab(entry, attribute)
        const_attribute = begin
          attribute.camelize.constantize
        rescue NameError
          attribute
        end

        case const_attribute
        when Hash
          dup_attribute = const_attribute.dup
          value = dup_attribute.delete("value")
          sprintf value, Hash[dup_attribute.map { |k, v| [k, grab(entry, v)] }].symbolize_keys
        when String
          normalize_ldap_value(entry, attribute)
        when Class, Module
          if const_attribute.respond_to?(:run)
            const_attribute.run(entry)
          else
            normalize_ldap_value(entry, attribute)
          end
        end
      end

      private

      def each_ldap_entry(attributes)
        search(:return_result => false, :filter => connection_config["filter"], :base => connection_config["basedn"], :attributes => attributes) do |entry|
          if grab(entry, attribute_mappings[EMAIL]).present? || (attribute_mappings.has_key?(UNIQUE_IDENTIFIER) && grab(entry, attribute_mappings[UNIQUE_IDENTIFIER]).present?)
            yield entry
          end
        end
      end

      def connection_config
        @config["connections"][connection_name]
      end

      def ldap_user_search_attributes
        mappings = []
        attribute_mappings.each_pair do |mapping_key, mapping_value|
          mappings << mapping_value unless mapping_key == PROFILE_PHOTO_ATTRIBUTE
        end
        attributes = search_attributes(mappings)
        attributes << permission_mappings.fetch('attribute_name', 'memberof')
        attributes.flatten
      end

      def ldap_photo_search_attributes
        search_attributes [attribute_mappings['email'], attribute_mappings['profile_photo']]
      end

      def search_attributes(mappings)
        mappings.map do |mapping_value|
          value = begin
            mapping_value.camelize.constantize
          rescue NameError
            mapping_value
          end

          case value
          when Hash
            dup_mapping_value = value.dup
            dup_mapping_value.delete("value")
            dup_mapping_value.values
          when String
            value
          when Class, Module
            if value.respond_to?(:attributes)
              value.attributes
            else
              mapping_value
            end
          end
        end
      end

      def search(search_options)
        options_for_search = if search_options[:base].present?
                               Array.wrap(search_options)
                             else
                               distinguished_names = Array.wrap(@ldap.search_root_dse.namingcontexts)
                               options_for_search = distinguished_names.map { |dn| search_options.merge(:base => dn ) }
                             end

        options_for_search.each do |options|
          @ldap.search(options) do |entry|
            yield(entry)
          end
        end
      end

      def normalize_ldap_value(entry, attribute)
        Array.wrap(entry[attribute]).compact.first
      end

      def permission_mappings
        @permission_mappings ||= connection_config['permission_mappings']
        @permission_mappings ||= @config.fetch 'permission_mappings', {}
      end

      def group_membership_mappings
        permission_mappings['group_memberships']
      end

      def dereference_mail(entry, dn_field, mail_attribute)
        @email_mapping ||= {}
        dn = grab(entry, dn_field)

        return @email_mapping[dn] if @email_mapping.key?(dn)

        @ldap.search(:base => dn, :scope => Net::LDAP::SearchScope_BaseObject) do |manager_entry|
          return @email_mapping[dn] = grab(manager_entry, mail_attribute)
        end
      end

      def group_unique_identifiers
        @group_uids ||= {}.tap do |groups|
          search_options = {
            :return_result => false,
            :filter => group_membership_mappings["filter"],
            :base => connection_config["basedn"],
            :attributes => [group_membership_mappings[UNIQUE_IDENTIFIER]]
          }

          search(search_options) do |entry|
            groups[grab(entry, "dn")] = grab(entry, group_membership_mappings[UNIQUE_IDENTIFIER])
          end
        end
      end

      def add_primary_attributes(entry, user_hash)
        PRIMARY_ATTRIBUTES.each do |attribute|
          next unless attribute_mappings.has_key?(attribute)
          user_hash[attribute] = grab(entry, attribute_mappings[attribute])
        end
      end

      def add_contact_attributes(entry, user_hash)
        user_hash['contact_info'] = {}
        CONTACT_ATTRIBUTES.each do |attribute|
          next unless attribute_mappings.has_key?(attribute)
          user_hash['contact_info'][attribute] = grab(entry, attribute_mappings[attribute])
        end
      end

      def add_custom_attributes(entry, user_hash)
        custom_attributes = attribute_mappings.keys - (PRIMARY_ATTRIBUTES + CONTACT_ATTRIBUTES + [PROFILE_PHOTO_ATTRIBUTE])

        user_hash['custom_fields'] = []
        custom_attributes.each do |attribute|
          if attribute == 'manager'
            user_hash['custom_fields'] << { 'id' => 'manager_email', 'label' => 'manager_email', 'value' => dereference_mail(entry, attribute_mappings[attribute], attribute_mappings[EMAIL]) }
          else
            user_hash['custom_fields'] << { 'id' => attribute, 'label' => attribute, 'value' => grab(entry, attribute_mappings[attribute]) }
          end
        end
      end

      def add_account_type(entry, user_hash)
        membership_attribute = permission_mappings.fetch 'attribute_name', 'memberof'
        memberships = entry[membership_attribute]
        external_ldap_groups = Array.wrap(permission_mappings.fetch('account_types', {})['external'])
        if external_ldap_groups.any? { |external_ldap_group| memberships.include?(external_ldap_group) }
          user_hash['account_type'] = 'external'
        else
          user_hash['account_type'] = 'member'
        end
      end

      def add_roles(entry, user_hash)
        return unless permission_roles_mappings = permission_mappings['roles']
        membership_attribute = permission_mappings.fetch 'attribute_name', 'memberof'
        memberships = entry[membership_attribute]

        user_hash['roles'] = []
        permission_roles_mappings.each_pair do |socialcast_role, ldap_groups|
          user_hash['roles'] << socialcast_role if Array.wrap(ldap_groups).any? { |ldap_group| memberships.include?(ldap_group) }
        end
      end

      def add_groups(entry, user_hash)
        return unless group_membership_mappings.present?

        membership_attribute = permission_mappings.fetch 'attribute_name', 'memberof'
        memberships = entry[membership_attribute]

        mapped_group_dns = (group_unique_identifiers.keys & memberships)

        user_hash['groups'] = mapped_group_dns.each_with_object([]) do |ldap_group_dn, socialcast_groups|
          socialcast_groups << group_unique_identifiers[ldap_group_dn]
        end
      end

      def build_user_hash_from_mappings(entry)
        user_hash = HashWithIndifferentAccess.new

        add_primary_attributes(entry, user_hash)
        add_contact_attributes(entry, user_hash)
        add_custom_attributes(entry, user_hash)
        add_account_type(entry, user_hash)
        add_roles(entry, user_hash) if user_hash['account_type'] == 'member'
        add_groups(entry, user_hash)

        user_hash
      end

      def build_photo_hash_from_mappings(entry)
        photo_hash = HashWithIndifferentAccess.new
        photo_hash[EMAIL] = grab(entry, attribute_mappings[EMAIL])
        photo_hash[PROFILE_PHOTO_ATTRIBUTE] = grab(entry, attribute_mappings[PROFILE_PHOTO_ATTRIBUTE])

        return photo_hash if photo_hash[EMAIL].present? && photo_hash[PROFILE_PHOTO_ATTRIBUTE].present?
      end
    end
  end
end
