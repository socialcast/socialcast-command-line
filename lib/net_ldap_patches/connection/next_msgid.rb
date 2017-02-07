module NetLDAPPatches
  module Connection
    module NextMsgid
      INITIAL_MSGID_ENV_VAR = 'NET_LDAP_INITIAL_MSGID'
      def next_msgid
        # avoids using the msgid range 128-255 by starting the msgid counter at 300
        # otherwise certain versions and/or configurations of Microsoft's Active Directory will
        # return Error Searching: invalid response-type in search: 24 and halt the mirroring process
        @msgid ||= ENV.key?(INITIAL_MSGID_ENV_VAR) ? ENV[INITIAL_MSGID_ENV_VAR].to_i : 300
        @msgid += 1
      end
    end
  end
end

Net::LDAP::Connection.prepend NetLDAPPatches::Connection::NextMsgid
