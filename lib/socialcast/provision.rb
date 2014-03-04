module Socialcast
  module Provision
    OUTPUT_FILE_NAME = 'users.xml.gz'

    class ProvisionError < StandardError; end

    def self.provision(ldap_config, options)
      options = options.dup
      options[:output] ||= OUTPUT_FILE_NAME

      http_config = ldap_config.fetch 'http', {}
      mappings = ldap_config.fetch 'mappings', {}
      permission_mappings = ldap_config.fetch 'permission_mappings', {}

      user_identifier_list = %w{email unique_identifier employee_number}
      user_whitelist = Set.new
      output_file = File.join Dir.pwd, options[:output]

      Zlib::GzipWriter.open(output_file) do |gz|
        xml = Builder::XmlMarkup.new(:target => gz, :indent => 1)
        xml.instruct!
        xml.export do |export|
          export.users(:type => "array") do |users|
            each_ldap_entry(ldap_config) do |ldap, entry|
              users.user do |user|
                entry.build_xml_from_mappings user, ldap, mappings, permission_mappings
              end
              user_whitelist << user_identifier_list.map { |identifier| entry.grab(mappings[identifier]) }
            end # connections
          end # users
        end # export
      end # gzip

      if options[:sanity_check]
        puts "Sanity checking users currently marked as needing to be terminated"
        ldap_connections(ldap_config) do |key, connection, ldap|
          (current_socialcast_users(http_config) - user_whitelist).each do |user_identifiers|
            combined_filters = []
            user_identifier_list.each_with_index do |identifier, index|
              combined_filters << ((mappings[identifier].blank? || user_identifiers[index].nil?) ? nil : Net::LDAP::Filter.eq(mappings[identifier], user_identifiers[index]))
            end
            combined_filters.compact!
            filter = ((combined_filters.size > 1) ? '(|%s)' : '%s') % combined_filters.join(' ')
            filter = Net::LDAP::Filter.construct(filter) & Net::LDAP::Filter.construct(connection["filter"])
            ldap_result = ldap.search(:return_result => true, :base => connection["basedn"], :filter => filter, :attributes => ldap_search_attributes(ldap_config))
            raise ProvisionError.new "Found user marked for termination that should not be terminated: #{user_identifiers}" unless ldap_result.blank?
          end
        end
      end

      if user_whitelist.empty? && !options[:force]
        raise ProvisionError.new "Skipping upload to Socialcast since no users were found"
      else
        puts "Uploading dataset to Socialcast..."
        resource = Socialcast.resource_for_path '/api/users/provision', http_config
        begin
          File.open(output_file, 'r') do |file|
            request_params = {:file => file}
            request_params[:skip_emails] = 'true' if (ldap_config['options']["skip_emails"] || options[:skip_emails])
            request_params[:test] = 'true' if (ldap_config['options']["test"] || options[:test])
            resource.post request_params, :accept => :json
          end
        rescue RestClient::Unauthorized => e
          raise ProvisionError.new "Authenticated user either does not have administration privileges or the community is not configured to allow provisioning. Please contact Socialcast support to if you need help." if e.http_code == 401
        end
        puts "Finished"
      end
      File.delete(output_file) if (ldap_config['options']['delete_users_file'] || options[:delete_users_file])
    end

    def self.sync_photos(ldap_config)
      http_config = ldap_config.fetch 'http', {}
      mappings = ldap_config.fetch 'mappings', {}
      mappings.fetch('profile_photo')

      search_users_resource = Socialcast.resource_for_path '/api/users/search', http_config

      each_ldap_entry(ldap_config) do |ldap, entry|
        email = entry.grab(mappings['email'])
        if profile_photo_data = entry.grab(mappings['profile_photo'])
          profile_photo_data = profile_photo_data.force_encoding('binary')

          user_search_response = search_users_resource.get(:params => { :q => email, :per_page => 1 }, :accept => :json)
          user_info = JSON.parse(user_search_response)['users'].first
          if user_info && user_info['avatars'] && user_info['avatars']['is_system_default']
            puts "Uploading photo for #{email}"

            user_resource = Socialcast.resource_for_path "/api/users/#{user_info['id']}", http_config
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

    def self.each_ldap_entry(config, &block)
      count = 0
      mappings = config.fetch 'mappings', {}

      ldap_connections(config) do |key, connection, ldap|
        ldap.search(:return_result => false, :filter => connection["filter"], :base => connection["basedn"], :attributes => ldap_search_attributes(config)) do |entry|

          if entry.grab(mappings["email"]).present? || (mappings.has_key?("unique_identifier") && entry.grab(mappings["unique_identifier"]).present?)
            yield ldap, entry
          end

          count += 1
          puts "Scanned #{count} users" if ((count % 100) == 0)
        end
      end
      puts "Finished scanning #{count} users"
    end


    def self.ldap_connections(config)
      config["connections"].each_pair do |key, connection|
        puts "Connecting to #{key} at #{[connection["host"], connection["port"]].join(':')}"
        ldap = create_ldap_instance(connection)
        puts "Searching base DN: #{connection["basedn"]} with filter: #{connection["filter"]}"
        yield key, connection, ldap
      end
    end

    def self.create_ldap_instance(connection)
      ldap = Net::LDAP.new :host => connection["host"], :port => connection["port"], :base => connection["basedn"]
      ldap.encryption connection['encryption'].to_sym if connection['encryption']
      ldap.auth connection["username"], connection["password"]
      ldap
    end

    def self.ldap_search_attributes(config)
      mappings = config.fetch 'mappings', {}
      permission_mappings = config.fetch 'permission_mappings', {}

      membership_attribute = permission_mappings.fetch 'attribute_name', 'memberof'
      attributes = mappings.values.map do |mapping_value|
        mapping_value = begin
          mapping_value.camelize.constantize
        rescue NameError
          mapping_value
        end
        case mapping_value
        when Hash
          dup_mapping_value = mapping_value.dup
          dup_mapping_value.delete("value")
          dup_mapping_value.values
        when String
          mapping_value
        when Class, Module
          fail "Please add the attributes method to #{mapping_value}" unless mapping_value.respond_to?(:attributes)
          mapping_value.attributes
        end
      end.flatten
      attributes << membership_attribute
    end

    def self.current_socialcast_users(http_config)
      current_socialcast_list = Set.new
      request_params = {:per_page => 500}
      request_params[:page] = 1
      resource = create_socialcast_user_index_request(http_config, request_params)
      while true
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

    def self.create_socialcast_user_index_request(http_config, request_params)
      path_template = "/api/users?per_page=%{per_page}&page=%{page}"
      Socialcast.resource_for_path((path_template % request_params), http_config)
    end
  end
end
