require 'net/ldap'

class Net::LDAP::Entry

  # grab a *single* value of an attribute
  # abstracts away ldap multivalue attributes
  def grab(attribute)
    Array.wrap(self[attribute]).compact.first
  end

  def build_xml_from_mappings(user, mappings = {}, permission_mappings = {})
    primary_attributes = %w{unique_identifier first_name last_name employee_number}
    primary_attributes.each do |attribute|
      next unless mappings.has_key?(attribute)
      user.tag! attribute, grab(mappings[attribute])
    end

    contact_attributes = %w{email location cell_phone office_phone}
    user.tag! 'contact-info' do |contact_info|
     contact_attributes.each do |attribute|
        next unless mappings.has_key?(attribute)
        contact_info.tag! attribute, grab(mappings[attribute])
      end
    end

    custom_attributes = mappings.keys - (primary_attributes + contact_attributes)
    user.tag! 'custom-fields', :type => "array" do |custom_fields|
      custom_attributes.each do |attribute|
        custom_fields.tag! 'custom-field' do |custom_field|
          custom_field.id attribute
          custom_field.label attribute
          custom_field.value grab(mappings[attribute])
        end
      end
    end

    membership_attribute = permission_mappings.fetch 'attribute_name', 'memberof'
    memberships = self[membership_attribute]
    external_ldap_groups = [permission_mappings.fetch('account_types', {})['external']].compact.flatten
    if external_ldap_groups.any? { |external_ldap_group| memberships.include?(external_ldap_group) }
      user.tag! 'account-type', 'external'
    else
      user.tag! 'account-type', 'member'
      if permission_roles_mappings = permission_mappings['roles']
        user.tag! 'roles', :type => 'array' do |roles|
          permission_roles_mappings.each_pair do |socialcast_role, ldap_groups|
            [ldap_groups].flatten.each do |ldap_group|
              if memberships.include?(ldap_group)
                roles.role socialcast_role
                break
              end
            end
          end
        end
      end
    end
  end
end
