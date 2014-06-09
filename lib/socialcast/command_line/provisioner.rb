module Socialcast
  module CommandLine
    module Provisioner
      class ProvisionError < StandardError; end

      DEFAULT_OUTPUT_FILE = 'users.xml.gz'

      def initialize(ldap_config, options = {})
        @ldap_config = ldap_config.dup
        @options = options.dup

        @options[:output] ||= DEFAULT_OUTPUT_FILE
      end

      private

      def http_config
        @http_config ||= @ldap_config.fetch 'http', {}
      end

      def each_ldap_connector
        @ldap_config['connections'].keys.each do |connection_name|
          LDAPConnector.with_connector(connection_name, @ldap_config) do |ldap_connector|
            yield ldap_connector
          end
        end
      end

      def each_ldap_entry(&block)
        count = 0

        each_ldap_connector do |connector|
          connector.each_ldap_entry do |entry|
            yield entry, connector.connection_name
            count += 1
            puts "Scanned #{count} users" if ((count % 100) == 0)
          end
        end
        puts "Finished scanning #{count} users"
      end
    end
  end
end