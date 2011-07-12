require 'net/ldap'

class Net::LDAP::Entry

  # grab a *single* value of an attribute
  # abstracts away ldap multivalue attributes
  def grab(attribute)
    Array.wrap(self[attribute]).compact.first
  end
end
