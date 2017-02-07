require 'spec_helper'

describe NetLdapPatches::Connection::NextMsgid do
  describe '#next_msgid' do
    context 'when ENV["NET_LDAP_INITIAL_MSGID"] is not present' do
      it { expect(Net::LDAP::Connection.new.next_msgid).to eq 301 }
    end
    context 'when ENV["NET_LDAP_INITIAL_MSGID"] is present' do
      before { ENV['NET_LDAP_INITIAL_MSGID'] = '5' }
      after { ENV.delete 'NET_LDAP_INITIAL_MSGID' }
      it { expect(Net::LDAP::Connection.new.next_msgid).to eq 6 }
    end
  end
end
