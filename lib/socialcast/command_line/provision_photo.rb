module Socialcast
  module CommandLine
    class ProvisionPhoto
      include Socialcast::CommandLine::Provisioner
      MAX_BATCH_SIZE = 50

      def sync(batch_size = MAX_BATCH_SIZE)
        assert_ldap_connections_support_photo!

        user_photos = {}

        debugger

        each_photo_hash do |photo_hash|
          email = photo_hash[LDAPConnector::EMAIL_ATTRIBUTE]
          user_photos[email] = photo_hash[LDAPConnector::PROFILE_PHOTO_ATTRIBUTE]
          if user_photos.size >= batch_size
            handle_batch(user_photos)
            user_photos = {}
          end
        end

        handle_batch(user_photos) if user_photos.any?
      end

      private

      def each_photo_hash
        each_ldap_connector do |connector|
          connector.each_photo_hash do |photo_hash|
            yield photo_hash
          end
        end
      end

      def assert_ldap_connections_support_photo!
        @ldap_config['connections'].each do |connection_name, _|
          unless LDAPConnector.attribute_mappings_for(connection_name, @ldap_config).key? LDAPConnector::PROFILE_PHOTO_ATTRIBUTE
            message = "Cannot sync photos: #{connection_name} does not have a mapping for the profile photo field."
            log(message)
            raise Socialcast::CommandLine::Provisioner::ProvisionError, message
          end
        end
      end

      def handle_batch(user_photos)
        search_users_resource = Socialcast::CommandLine.resource_for_path '/api/users/search', http_config
        user_emails_query = user_photos.map { |email, _| "\"#{email}\"" }.join(" OR ")
        user_search_response = search_users_resource.get(:params => { :q => user_emails_query, :per_page => MAX_BATCH_SIZE }, :accept => :json)
        JSON.parse(user_search_response)['users'].each do |user_hash|
          email = user_hash['contact_info']['email']
          sync_photo(user_hash, user_photos[email])
        end
      end

      def sync_photo(user_hash, profile_photo_data)
        is_system_default = user_hash && user_hash['avatars'] && user_hash['avatars']['is_system_default']
        is_community_default = user_hash && user_hash['avatars'] && (user_hash['avatars']['id'] == default_profile_photo_id)
        user_email = user_hash && user_hash['contact_info'] && user_hash['contact_info']['email']
        return unless is_system_default || is_community_default || @options[:force_sync]

        log "Syncing photo for #{user_email}"

        if profile_photo_data && file = photo_data_to_file(profile_photo_data)
          begin
            log "Uploading photo for #{user_email}"
            user_resource = Socialcast::CommandLine.resource_for_path "/api/users/#{user_hash['id']}", http_config
            user_resource.put({ :user => { :profile_photo => { :data => file } } })
          ensure
            file.unlink
          end
        end
      end

      def photo_data_to_file(profile_photo_data)
        if profile_photo_data.start_with?('http')
          profile_photo_data = download_photo_data(profile_photo_data)
          return unless profile_photo_data
        end

        ## FORCE ENCODING
        profile_photo_data = profile_photo_data.force_encoding('binary')

        ## CONTENT TYPE
        unless content_type = binary_to_content_type(profile_photo_data)
          log "Skipping photo: unknown image format (supports .gif, .png, .jpg)"
          return
        end

        ## WRITE TEMP FILE
        Tempfile.new(["photo_upload", ".#{content_type}"]).tap do |tempfile|
          tempfile.binmode
          tempfile.write(profile_photo_data)
          tempfile.rewind
        end
      end

      def download_photo_data(profile_photo_data)
        RestClient.get(profile_photo_data)
      rescue => e
        log "Unable to download photo #{profile_photo_data}"
        log e.response
      end

      def default_profile_photo_id
        @default_profile_photo_id ||= Socialcast::CommandLine::Authenticate.current_user['community']['default_profile_photo_id']
      end

      def binary_to_content_type(binary_photo_data)
        case binary_photo_data
        when Regexp.new("^GIF8", nil, 'n')
          'gif'
        when Regexp.new('^\x89PNG', nil, 'n')
          'png'
        when Regexp.new("^\xff\xd8\xff\xe0\x00\x10JFIF", nil, 'n'), Regexp.new("^\xff\xd8\xff\xe1(.*){2}Exif", nil, 'n')
          'jpg'
        end
      end
    end
  end
end
