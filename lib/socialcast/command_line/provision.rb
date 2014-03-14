require 'net/ldap'

require 'zlib'
require 'builder'
require 'set'
require 'fileutils'

module Socialcast
  module CommandLine
    class Provision
      DEFAULT_OUTPUT_FILE = 'users.xml.gz'

      class ProvisionError < StandardError; end

      def initialize(ldap_config, options = {})
        @ldap_config = ldap_config.dup
        @options = options.dup

        @options[:output] ||= DEFAULT_OUTPUT_FILE
      end

      def each_user_hash
        each_ldap_entry do |ldap, entry, attr_mappings, perm_mappings|
          yield build_user_hash_from_mappings(ldap, entry, attr_mappings, perm_mappings)
        end
      end

      def provision
        http_config = @ldap_config.fetch 'http', {}

        user_whitelist = Set.new
        output_file = File.join Dir.pwd, @options[:output]

        Zlib::GzipWriter.open(output_file) do |gz|
          xml = Builder::XmlMarkup.new(:target => gz, :indent => 1)
          xml.instruct!
          xml.export do |export|
            export.users(:type => "array") do |users|
              each_user_hash do |user_hash|
                users << user_hash.to_xml(:skip_instruct => true, :root => 'user')
                user_whitelist << [user_hash['contact_info']['email'], user_hash['unique_identifier'], user_hash['employee_number']]
              end
            end # users
          end # export
        end # gzip

        if @options[:sanity_check]
          puts "Sanity checking users currently marked as needing to be terminated"
          each_ldap_connection do |ldap_connection_name, connection, ldap|
            attr_mappings = attribute_mappings(ldap_connection_name)
            (current_socialcast_users(http_config) - user_whitelist).each do |user_identifiers|
              combined_filters = []
              ['email', 'unique_identifier', 'employee_number'].each_with_index do |identifier, index|
                combined_filters << ((attr_mappings[identifier].blank? || user_identifiers[index].nil?) ? nil : Net::LDAP::Filter.eq(attr_mappings[identifier], user_identifiers[index]))
              end
              combined_filters.compact!
              filter = ((combined_filters.size > 1) ? '(|%s)' : '%s') % combined_filters.join(' ')
              filter = Net::LDAP::Filter.construct(filter) & Net::LDAP::Filter.construct(connection["filter"])
              ldap_result = ldap.search(:return_result => true, :base => connection["basedn"], :filter => filter, :attributes => ldap_search_attributes(ldap_connection_name))
              raise ProvisionError.new "Found user marked for termination that should not be terminated: #{user_identifiers}" unless ldap_result.blank?
            end
          end
        end

        if user_whitelist.empty? && !@options[:force]
          raise ProvisionError.new "Skipping upload to Socialcast since no users were found"
        else
          puts "Uploading dataset to Socialcast..."
          resource = Socialcast::CommandLine.resource_for_path '/api/users/provision', http_config
          begin
            File.open(output_file, 'r') do |file|
              request_params = {:file => file}
              request_params[:skip_emails] = 'true' if (@ldap_config['options']["skip_emails"] || @options[:skip_emails])
              request_params[:test] = 'true' if (@ldap_config['options']["test"] || @options[:test])
              resource.post request_params, :accept => :json
            end
          rescue RestClient::Unauthorized => e
            raise ProvisionError.new "Authenticated user either does not have administration privileges or the community is not configured to allow provisioning. Please contact Socialcast support to if you need help." if e.http_code == 401
          end
          puts "Finished"
        end
        File.delete(output_file) if (@ldap_config['options']['delete_users_file'] || @options[:delete_users_file])
      end

      def sync_photos
        http_config = @ldap_config.fetch 'http', {}

        @ldap_config["connections"].keys.each do |ldap_connection_name|
          attribute_mappings(ldap_connection_name).fetch('profile_photo')
        end

        search_users_resource = Socialcast::CommandLine.resource_for_path '/api/users/search', http_config

        each_ldap_entry do |ldap, entry, attr_mappings, _|
          email = grab(entry, attr_mappings['email'])
          if profile_photo_data = grab(entry, attr_mappings['profile_photo'])
            profile_photo_data = profile_photo_data.force_encoding('binary')

            user_search_response = search_users_resource.get(:params => { :q => email, :per_page => 1 }, :accept => :json)
            user_info = JSON.parse(user_search_response)['users'].first
            if user_info && user_info['avatars'] && user_info['avatars']['is_system_default']
              puts "Uploading photo for #{email}"

              user_resource = Socialcast::CommandLine.resource_for_path "/api/users/#{user_info['id']}", http_config
              content_type = case profile_photo_data
              when Regexp.new("\AGIF8", nil, 'n')
                'gif'
              when Regexp.new('\A\x89PNG', nil, 'n')
                'png'
              when Regexp.new("\A\xff\xd8\xff\xe0\x00\x10JFIF", nil, 'n'), Regexp.new("\A\xff\xd8\xff\xe1(.*){2}Exif", nil, 'n')
                'jpg'
              else
                puts "Skipping photo for #{email}: unknown image format (supports .gif, .png, .jpg)"
                next
              end

              tempfile = Tempfile.new(["photo_upload", ".#{content_type}"])
              tempfile.write(profile_photo_data)
              tempfile.rewind
              begin
                user_resource.put({ :user => { :profile_photo => { :data => tempfile } } })
              ensure
                tempfile.unlink
              end
            end
          end
        end
      end

      private

      def dereference_mail(entry, ldap_connection, dn_field, mail_attribute)
        dn = grab(entry, dn_field)
        ldap_connection.search(:base => dn, :scope => Net::LDAP::SearchScope_BaseObject) do |manager_entry|
          return grab(manager_entry, mail_attribute)
        end
      end

      def build_user_hash_from_mappings(ldap_connection, entry, attr_mappings, perm_mappings)
        user_hash = HashWithIndifferentAccess.new
        primary_attributes = %w{unique_identifier first_name last_name employee_number}
        primary_attributes.each do |attribute|
          next unless attr_mappings.has_key?(attribute)
          user_hash[attribute] = grab(entry, attr_mappings[attribute])
        end

        contact_attributes = %w{email location cell_phone office_phone}
        user_hash['contact_info'] = {}
        contact_attributes.each do |attribute|
          next unless attr_mappings.has_key?(attribute)
          user_hash['contact_info'][attribute] = grab(entry, attr_mappings[attribute])
        end

        custom_attributes = attr_mappings.keys - (primary_attributes + contact_attributes)

        user_hash['custom_fields'] = []
        custom_attributes.each do |attribute|
          if attribute == 'manager'
            user_hash['custom_fields'] << { 'id' => 'manager_email', 'label' => 'manager_email', 'value' => dereference_mail(entry, ldap_connection, attr_mappings[attribute], attr_mappings['email']) }
          else
            user_hash['custom_fields'] << { 'id' => attribute, 'label' => attribute, 'value' => grab(entry, attr_mappings[attribute]) }
          end
        end

        membership_attribute = perm_mappings.fetch 'attribute_name', 'memberof'
        memberships = entry[membership_attribute]
        external_ldap_groups = Array.wrap(perm_mappings.fetch('account_types', {})['external'])
        if external_ldap_groups.any? { |external_ldap_group| memberships.include?(external_ldap_group) }
          user_hash['account_type'] = 'external'
        else
          user_hash['account_type'] = 'member'
          if permission_roles_mappings = perm_mappings['roles']
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


      def each_ldap_entry(&block)
        count = 0

        each_ldap_connection do |ldap_connection_name, connection, ldap|
          attr_mappings = attribute_mappings(ldap_connection_name)
          perm_mappings = permission_mappings(ldap_connection_name)
          ldap.search(:return_result => false, :filter => connection["filter"], :base => connection["basedn"], :attributes => ldap_search_attributes(ldap_connection_name)) do |entry|
            if grab(entry, attr_mappings["email"]).present? || (attr_mappings.has_key?("unique_identifier") && grab(entry, attr_mappings["unique_identifier"]).present?)
              yield ldap, entry, attr_mappings, perm_mappings
            end

            count += 1
            puts "Scanned #{count} users" if ((count % 100) == 0)
          end
        end
        puts "Finished scanning #{count} users"
      end


      def each_ldap_connection
        @ldap_config["connections"].each_pair do |ldap_connection_name, connection|
          puts "Connecting to #{ldap_connection_name} at #{[connection["host"], connection["port"]].join(':')}"
          ldap = create_ldap_instance(connection)
          puts "Searching base DN: #{connection["basedn"]} with filter: #{connection["filter"]}"
          yield ldap_connection_name, connection, ldap
        end
      end

      def create_ldap_instance(connection)
        ldap = Net::LDAP.new :host => connection["host"], :port => connection["port"], :base => connection["basedn"]
        ldap.encryption connection['encryption'].to_sym if connection['encryption']
        ldap.auth connection["username"], connection["password"]
        ldap
      end

      def ldap_search_attributes(ldap_connection_name)
        attr_mappings = attribute_mappings(ldap_connection_name)
        perm_mappings = permission_mappings(ldap_connection_name)

        membership_attribute = perm_mappings.fetch 'attribute_name', 'memberof'
        attributes = attr_mappings.values.map do |mapping_value|
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

      def current_socialcast_users(http_config)
        current_socialcast_list = Set.new
        request_params = {:per_page => 500}
        request_params[:page] = 1
        resource = create_socialcast_user_index_request(http_config, request_params)
        loop do
          response = resource.get :accept => :json
          result = JSON.parse(response)
          users = result["users"]
          break if users.blank?
          request_params[:page] += 1
          resource = create_socialcast_user_index_request(http_config, request_params)
          users.each do |user|
            current_socialcast_list << [user['contact_info']['email'], user['company_login'], user['employee_number']]
          end
        end
        current_socialcast_list
      end

      def create_socialcast_user_index_request(http_config, request_params)
        path_template = "/api/users?per_page=%{per_page}&page=%{page}"
        Socialcast::CommandLine.resource_for_path((path_template % request_params), http_config)
      end

      def attribute_mappings(connection_name)
        @attribute_mappings ||= {}

        unless @attribute_mappings[connection_name]
          @attribute_mappings[connection_name] = @ldap_config['connections'][connection_name].fetch 'mappings', nil
          @attribute_mappings[connection_name] ||= @ldap_config.fetch 'mappings', {}
        end

        @attribute_mappings[connection_name]
      end

      def permission_mappings(connection_name)
        @permission_mappings ||= {}

        unless @permission_mappings[connection_name]
          @permission_mappings[connection_name] = @ldap_config['connections'][connection_name].fetch 'permission_mappings', nil
          @permission_mappings[connection_name] ||= @ldap_config.fetch 'permission_mappings', {}
        end

        @permission_mappings[connection_name]
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

      def normalize_ldap_value(entry, attribute)
        Array.wrap(entry[attribute]).compact.first
      end
    end
  end
end
