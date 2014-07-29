module Socialcast
  module CommandLine
    class ProvisionPhoto
      include Socialcast::CommandLine::Provisioner

      attr_accessor :sync_strategy

      def sync(strategy_klass = ApiSyncStrategy)
        assert_no_unsupported_configurations

        sync_strategy = strategy_klass.new(self)
        process_options = {
          :http_config => http_config,
          :force_sync => @options[:force_sync]
        }

        user_photos = {}

        each_photo_hash do |photo_hash|
          email = photo_hash[LDAPConnector::EMAIL_ATTRIBUTE]
          user_photos[email] = photo_hash[LDAPConnector::PROFILE_PHOTO_ATTRIBUTE]
          if user_photos.size >= sync_strategy.batch_size
            sync_strategy.process(user_photos, process_options)
            user_photos = {}
          end
        end

        sync_strategy.process(user_photos, process_options) if user_photos.any?
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

      def default_profile_photo_id
        @default_profile_photo_id ||= Socialcast::CommandLine::Authenticate.current_user['community']['default_profile_photo_id']
      end

      def configured?
        unsupported_configurations.none?
      end

      def unsupported_configurations
        @unsupported_configurations ||= @ldap_config['connections'].reject do |connection_name, _|
          LDAPConnector.attribute_mappings_for(connection_name, @ldap_config).key? LDAPConnector::PROFILE_PHOTO_ATTRIBUTE
        end.keys
      end

      protected

      def each_photo_hash
        each_ldap_connector do |connector|
          connector.each_photo_hash do |photo_hash|
            yield photo_hash
          end
        end
      end

      def assert_no_unsupported_configurations
        unless configured?
          connection_names = unsupported_configurations
          message = "Cannot sync photos: #{connection_names.join(', ')} do not have a mapping for the profile photo field."
          log(message)
          raise Socialcast::CommandLine::Provisioner::ProvisionError, message
        end
      end

      def download_photo_data(profile_photo_data)
        RestClient.get(profile_photo_data)
      rescue => e
        log "Unable to download photo #{profile_photo_data}"
        log e.response
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

      class ApiSyncStrategy
        attr_reader :provisioner
        attr_reader :http_config

        MAX_BATCH_SIZE = 50

        def initialize(provisioner)
          @provisioner = provisioner
        end

        def process(user_photos, options = {})
          @http_config = options[:http_config]
          @force_sync = options[:force_sync]

          search_users_resource = Socialcast::CommandLine.resource_for_path '/api/users/search', http_config
          user_emails_query = user_photos.map { |email, _| "\"#{email}\"" }.join(" OR ")
          user_search_response = search_users_resource.get(:params => { :q => user_emails_query, :per_page => batch_size }, :accept => :json)
          JSON.parse(user_search_response)['users'].each do |user_hash|
            email = user_hash['contact_info']['email']
            sync_photo(user_hash, user_photos[email])
          end
        end

        def batch_size
          MAX_BATCH_SIZE
        end

        private

        def sync_photo(user_hash, profile_photo_data)
          is_system_default = user_hash && user_hash['avatars'] && user_hash['avatars']['is_system_default']
          is_community_default = user_hash && user_hash['avatars'] && (user_hash['avatars']['id'] == provisioner.default_profile_photo_id)
          user_email = user_hash && user_hash['contact_info'] && user_hash['contact_info']['email']
          return unless is_system_default || is_community_default || force_sync?

          log "Syncing photo for #{user_email}"

          if profile_photo_data && file = provisioner.photo_data_to_file(profile_photo_data)
            begin
              log "Uploading photo for #{user_email}"
              user_resource = Socialcast::CommandLine.resource_for_path "/api/users/#{user_hash['id']}", http_config
              user_resource.put({ :user => { :profile_photo => { :data => file } } })
            ensure
              file.unlink
            end
          end
        end

        def force_sync?
          !!@force_sync
        end

        def log(message)
          provisioner.send(:log, message)
        end
      end

    end
  end
end
