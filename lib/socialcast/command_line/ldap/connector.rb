require 'net/ldap'
require 'active_support/core_ext/object/blank'
require 'active_support/core_ext/array/wrap'

module Socialcast
  module CommandLine
    module LDAP
      class Connector
        attr_reader :attribute_mappings, :connection_name

        def initialize(connection_name, config)
          @connection_name = connection_name
          @config = config
        end

        def each_user_hash
          each_ldap_entry do |entry|
            yield build_user_hash_from_mappings(entry)
          end
        end

        def each_ldap_entry
          search(:return_result => false, :filter => connection_config["filter"], :base => connection_config["basedn"], :attributes => ldap_search_attributes) do |entry|
            if grab(entry, attribute_mappings["email"]).present? || (attribute_mappings.has_key?("unique_identifier") && grab(entry, attribute_mappings["unique_identifier"]).present?)
              yield entry
            end
          end
        end

        def fetch_user_hash(identifier, options)
          options = options.dup
          identifying_field = options.delete(:identifying_field) || 'unique_identifier'

          filter = if connection_config['filter'].present?
                     Net::LDAP::Filter.construct(connection_config['filter'])
                   else
                     Net::LDAP::Filter.pres("objectclass")
                   end

          filter = filter & Net::LDAP::Filter.construct("#{attribute_mappings[identifying_field]}=#{identifier}")

          search(:base => connection_config['basedn'], :filter => filter, :attributes => ldap_search_attributes, :size => 1) do |entry|
            return build_user_hash_from_mappings(entry)
          end

          nil
        end

        def ldap_search_attributes
          membership_attribute = permission_mappings.fetch 'attribute_name', 'memberof'
          attributes = attribute_mappings.values.map do |mapping_value|
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
          end.flatten
          attributes << membership_attribute
        end

        def attribute_mappings
          @attribute_mappings ||= connection_config.fetch 'mappings', nil
          @attribute_mappings ||= @config.fetch 'mappings', {}
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

        def connection_config
          @config["connections"][connection_name]
        end

        private

        def ldap
          @ldap ||= Net::LDAP.new(:host => connection_config["host"], :port => connection_config["port"], :base => connection_config["basedn"]).tap do |ldap_instance|
            ldap_instance.encryption connection_config['encryption'].to_sym if connection_config['encryption']
            ldap_instance.auth connection_config["username"], connection_config["password"]
          end
        end

        def search(search_options)
          options_for_search = if search_options[:base].present?
                                 Array.wrap(search_options)
                               else
                                 distinguished_names = Array.wrap(ldap.search_root_dse.namingcontexts)
                                 options_for_search = distinguished_names.map { |dn| search_options.merge(:base => dn ) }
                               end

          options_for_search.each do |options|
            ldap.search(options) do |entry|
              yield(entry)
            end
          end
        end

        def normalize_ldap_value(entry, attribute)
          Array.wrap(entry[attribute]).compact.first
        end

        def permission_mappings
          @permission_mappings ||= connection_config.fetch 'permission_mappings', nil
          @permission_mappings ||= @config.fetch 'permission_mappings', {}
        end

        def dereference_mail(entry, dn_field, mail_attribute)
          dn = grab(entry, dn_field)
          ldap.search(:base => dn, :scope => Net::LDAP::SearchScope_BaseObject) do |manager_entry|
            return grab(manager_entry, mail_attribute)
          end
        end

        def build_user_hash_from_mappings(entry)
          user_hash = HashWithIndifferentAccess.new
          primary_attributes = %w{unique_identifier first_name last_name employee_number}
          primary_attributes.each do |attribute|
            next unless attribute_mappings.has_key?(attribute)
            user_hash[attribute] = grab(entry, attribute_mappings[attribute])
          end

          contact_attributes = %w{email location cell_phone office_phone}
          user_hash['contact_info'] = {}
          contact_attributes.each do |attribute|
            next unless attribute_mappings.has_key?(attribute)
            user_hash['contact_info'][attribute] = grab(entry, attribute_mappings[attribute])
          end

          custom_attributes = attribute_mappings.keys - (primary_attributes + contact_attributes)

          user_hash['custom_fields'] = []
          custom_attributes.each do |attribute|
            if attribute == 'manager'
              user_hash['custom_fields'] << { 'id' => 'manager_email', 'label' => 'manager_email', 'value' => dereference_mail(entry, attribute_mappings[attribute], attribute_mappings['email']) }
            else
              user_hash['custom_fields'] << { 'id' => attribute, 'label' => attribute, 'value' => grab(entry, attribute_mappings[attribute]) }
            end
          end

          membership_attribute = permission_mappings.fetch 'attribute_name', 'memberof'
          memberships = entry[membership_attribute]
          external_ldap_groups = Array.wrap(permission_mappings.fetch('account_types', {})['external'])
          if external_ldap_groups.any? { |external_ldap_group| memberships.include?(external_ldap_group) }
            user_hash['account_type'] = 'external'
          else
            user_hash['account_type'] = 'member'
            if permission_roles_mappings = permission_mappings['roles']
              user_hash['roles'] = []
              permission_roles_mappings.each_pair do |socialcast_role, ldap_groups|
                Array.wrap(ldap_groups).each do |ldap_group|
                  if memberships.include?(ldap_group)
                    user_hash['roles'] << socialcast_role
                    break
                  end
                end
              end
            end
          end

          user_hash
        end
      end
    end
  end
end
