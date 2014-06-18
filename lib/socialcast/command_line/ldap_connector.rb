require 'net/ldap'
require 'active_support/core_ext/object/blank'
require 'active_support/core_ext/array/wrap'

module Socialcast
  module CommandLine
    class LDAPConnector
      class ConcurrentSearchError < StandardError; end

      UNIQUE_IDENTIFIER_ATTRIBUTE = "unique_identifier"
      EMAIL_ATTRIBUTE = "email"
      MANAGER_ATTRIBUTE = "manager"
      PRIMARY_ATTRIBUTES = [UNIQUE_IDENTIFIER_ATTRIBUTE, 'first_name', 'last_name', 'employee_number']
      CONTACT_ATTRIBUTES = [EMAIL_ATTRIBUTE, 'location', 'cell_phone', 'office_phone']
      PROFILE_PHOTO_ATTRIBUTE = 'profile_photo'

      attr_reader :attribute_mappings, :connection_name

      def self.attribute_mappings_for(connection_name, config)
        config['connections'][connection_name]['mappings'] || config.fetch('mappings', {})
      end

      def initialize(connection_name, config)
        @connection_name = connection_name
        @config = config
      end

      def each_user_hash
        ldap.open do
          fetch_group_unique_identifiers
          fetch_dn_to_email_hash

          each_ldap_entry(ldap_user_search_attributes) do |entry|
            yield build_user_hash_from_mappings(entry)
          end
        end
      end

      def each_photo_hash
        ldap.open do
          each_ldap_entry(ldap_photo_search_attributes) do |entry|
            photo_hash = build_photo_hash_from_mappings(entry)
            yield photo_hash if photo_hash.present?
          end
        end
      end

      def fetch_user_hash(identifier, options)
        ldap.open do
          fetch_group_unique_identifiers
          fetch_dn_to_email_hash

          options = options.dup
          identifying_field = options.delete(:identifying_field) || UNIQUE_IDENTIFIER_ATTRIBUTE

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
      end

      def attribute_mappings
        @attribute_mappings ||= LDAPConnector.attribute_mappings_for(@connection_name, @config)
      end

      private

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

      def ldap
        @ldap ||= Net::LDAP.new(:host => connection_config["host"], :port => connection_config["port"], :base => connection_config["basedn"]).tap do |ldap_instance|
          ldap_instance.encryption connection_config['encryption'].to_sym if connection_config['encryption']
          ldap_instance.auth connection_config["username"], connection_config["password"]
        end
      end

      def root_namingcontexts
        @root_naming_contexts ||= Array.wrap(@ldap.search_root_dse.namingcontexts)
      end

      def each_ldap_entry(attributes)
        search(:return_result => false, :filter => connection_config["filter"], :base => connection_config["basedn"], :attributes => attributes) do |entry|
          if grab(entry, attribute_mappings[EMAIL_ATTRIBUTE]).present? || (attribute_mappings.has_key?(UNIQUE_IDENTIFIER_ATTRIBUTE) && grab(entry, attribute_mappings[UNIQUE_IDENTIFIER_ATTRIBUTE]).present?)
            yield entry
          end
        end
      end

      def connection_config
        @config["connections"][connection_name]
      end

      def ldap_mail_search_attributes
        search_attributes [attribute_mappings[LDAPConnector::EMAIL_ATTRIBUTE]]
      end

      def ldap_user_search_attributes
        mappings = attribute_mappings.map do |mapping_key, mapping_value|
          mapping_value unless mapping_key == PROFILE_PHOTO_ATTRIBUTE
        end.compact
        attributes = search_attributes(mappings)
        attributes << permission_mappings.fetch('attribute_name', 'memberof')
        attributes.flatten
      end

      def ldap_photo_search_attributes
        search_attributes [attribute_mappings[LDAPConnector::EMAIL_ATTRIBUTE], attribute_mappings[LDAPConnector::PROFILE_PHOTO_ATTRIBUTE]]
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
        raise ConcurrentSearchError.new "Cannot perform concurrent searches on an open ldap connection" if @search_in_progress
        begin
          options_for_search = if search_options[:base].present?
                                 Array.wrap(search_options)
                               else
                                 options_for_search = root_namingcontexts.map { |dn| search_options.merge(:base => dn ) }
                               end

          options_for_search.each do |options|
            @search_in_progress = true

            @ldap.search(options) do |entry|
              yield(entry)
            end

          end
        ensure
          @search_in_progress = false
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

      def dereference_mail(entry, dn_field)
        dn = grab(entry, dn_field)

        @dn_to_email_hash[dn]
      end

      def fetch_group_unique_identifiers
        @group_unique_identifiers ||= if group_membership_mappings.present?
                                        {}.tap do |groups|
                                          search_options = {
                                            :return_result => false,
                                            :filter => group_membership_mappings["filter"],
                                            :base => connection_config["basedn"],
                                            :attributes => [group_membership_mappings[UNIQUE_IDENTIFIER_ATTRIBUTE]]
                                          }

                                          search(search_options) do |entry|
                                            groups[grab(entry, "dn")] = grab(entry, group_membership_mappings[UNIQUE_IDENTIFIER_ATTRIBUTE])
                                          end
                                        end
                                      else
                                        {}
                                      end
      end

      def fetch_dn_to_email_hash
        @dn_to_email_hash ||= if attribute_mappings[MANAGER_ATTRIBUTE].present?
                                {}.tap do |dn_to_email_hash|
                                  each_ldap_entry(ldap_mail_search_attributes) do |entry|
                                    dn_to_email_hash[entry.dn] = grab(entry, attribute_mappings[EMAIL_ATTRIBUTE])
                                  end
                                end
                              else
                                {}
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
          if attribute == MANAGER_ATTRIBUTE
            user_hash['custom_fields'] << { 'id' => 'manager_email', 'label' => 'manager_email', 'value' => dereference_mail(entry, attribute_mappings[attribute]) }
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

        mapped_group_dns = (@group_unique_identifiers.keys & memberships)

        user_hash['groups'] = mapped_group_dns.each_with_object([]) do |ldap_group_dn, socialcast_groups|
          socialcast_groups << @group_unique_identifiers[ldap_group_dn]
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
        photo_hash[EMAIL_ATTRIBUTE] = grab(entry, attribute_mappings[EMAIL_ATTRIBUTE])
        photo_hash[PROFILE_PHOTO_ATTRIBUTE] = grab(entry, attribute_mappings[PROFILE_PHOTO_ATTRIBUTE])

        return photo_hash if photo_hash[EMAIL_ATTRIBUTE].present? && photo_hash[PROFILE_PHOTO_ATTRIBUTE] && !photo_hash[PROFILE_PHOTO_ATTRIBUTE].empty?
      end
    end
  end
end
