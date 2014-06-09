module Socialcast
  module CommandLine
    class ProvisionPhoto
      include Socialcast::CommandLine::Provisioner
      attr_accessor :users
      MAX_BATCH_SIZE = 50

      def sync
        @ldap_config['connections'].keys.each do |connection_name|
          LDAPConnector.attribute_mappings_for(connection_name, @ldap_config).fetch(LDAPConnector::PROFILE_PHOTO_ATTRIBUTE)
        end

        init_users

        each_ldap_connector do |connector|
          connector.each_photo_hash do |photo_hash|
            email = photo_hash[LDAPConnector::EMAIL_ATTRIBUTE]
            users[email] = photo_hash[LDAPConnector::PROFILE_PHOTO_ATTRIBUTE]
            handle_batch if users.size >= MAX_BATCH_SIZE
          end
        end

        handle_batch if users.any?
      end

      private

      def init_users
        @users = {}
      end

      def handle_batch
        users.each_slice(MAX_BATCH_SIZE) do |user_batch|
          search_users_resource = Socialcast::CommandLine.resource_for_path '/api/users/search', http_config
          user_emails_query = user_batch.map { |u| "\"#{u[0]}\"" }.join(" OR ")
          user_search_response = search_users_resource.get(:params => { :q => user_emails_query, :per_page => MAX_BATCH_SIZE }, :accept => :json)
          JSON.parse(user_search_response)['users'].each do |user_hash|
            sync_photo_for(user_hash)
          end
        end

        init_users
      end

      def sync_photo_for(user_hash)
        is_community_default = user_hash && user_hash['avatars'] && user_hash['avatars']['is_community_default']
        user_email = user_hash && user_hash['contact_info'] && user_hash['contact_info']['email']
        return unless is_community_default || @options[:force_sync]

        ## PHOTO URL TO BINARY
        if profile_photo_data = users[user_email]
          if profile_photo_data.start_with?('http')
            begin
              profile_photo_data = RestClient.get(profile_photo_data)
            rescue => e
              puts "Unable to download photo #{profile_photo_data} for #{user_email}"
              puts e.response
              return
            end
          end

          ## FORCE ENCODING
          profile_photo_data = profile_photo_data.force_encoding('binary')

          ## CONTENT TYPE
          unless content_type = binary_to_content_type(profile_photo_data)
            puts "Skipping photo for #{user_email}: unknown image format (supports .gif, .png, .jpg)"
            return
          end

          ## WRITE TEMP FILE
          tempfile = Tempfile.new(["photo_upload", ".#{content_type}"])
          tempfile.binmode
          tempfile.write(profile_photo_data)
          tempfile.rewind

          puts "Uploading photo for #{user_email}"

          ## SUBMIT PHOTO
          begin
            user_resource = Socialcast::CommandLine.resource_for_path "/api/users/#{user_hash['id']}", http_config
            user_resource.put({ :user => { :profile_photo => { :data => tempfile } } })
          ensure
            tempfile.unlink
          end
        end
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