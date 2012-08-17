require 'net/ldap'

class Net::LDAP::Entry

  # grab a *single* value of an attribute
  # abstracts away ldap multivalue attributes
  def grab(attribute)
    attribute = begin
      attribute.constantize
    rescue NameError
      attribute
    end

    case attribute
    when Hash
      value = attribute.delete("value")
      value % Hash[attribute.map {|k,v| [k, grab(v)]}].symbolize_keys
    when String
      Array.wrap(self[attribute]).compact.first
    when Class, Module
      return nil unless attribute.respond_to?(:run)
      attribute.run(self)
    end
  end

  def dereference_mail(ldap_connection, dn_field, mail_attribute)
    dn = grab(dn_field)
    ldap_connection.search(:base => dn, :scope => Net::LDAP::SearchScope_BaseObject) do |entry|
      return entry.grab(mail_attribute)
    end
  end

  def build_xml_from_mappings(user, ldap_connection, mappings = {}, permission_mappings = {})
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
          if attribute == 'manager'
            custom_field.id 'manager_email'
            custom_field.label 'manager_email'
            custom_field.value dereference_mail(ldap_connection, mappings[attribute], mappings['email'])
          else
            custom_field.id attribute
            custom_field.label attribute
            custom_field.value grab(mappings[attribute])
          end
        end
      end
    end

    membership_attribute = permission_mappings.fetch 'attribute_name', 'memberof'
    memberships = self[membership_attribute]
    external_ldap_groups = Array.wrap(permission_mappings.fetch('account_types', {})['external'])
    if external_ldap_groups.any? { |external_ldap_group| memberships.include?(external_ldap_group) }
      user.tag! 'account-type', 'external'
    else
      user.tag! 'account-type', 'member'
      if permission_roles_mappings = permission_mappings['roles']
        user.tag! 'roles', :type => 'array' do |roles|
          permission_roles_mappings.each_pair do |socialcast_role, ldap_groups|
            Array.wrap(ldap_groups).each do |ldap_group|
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
