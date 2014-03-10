require 'net/ldap'

class Net::LDAP::Entry

  # grab a *single* value of an attribute
  # abstracts away ldap multivalue attributes
  def grab(attribute)
    attribute = begin
      attribute.camelize.constantize
    rescue NameError
      attribute
    end

    case attribute
    when Hash
      dup_attribute = attribute.dup
      value = dup_attribute.delete("value")
      value % Hash[dup_attribute.map {|k,v| [k, grab(v)]}].symbolize_keys
    when String
      Array.wrap(self[attribute]).compact.first
    when Class, Module
      return nil unless attribute.respond_to?(:run)
      attribute.run(self)
    end
  end
end
