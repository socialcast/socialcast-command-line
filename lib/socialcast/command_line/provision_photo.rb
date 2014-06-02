require 'digest/md5'

module Socialcast
  module CommandLine
    class ProvisionPhoto
      include Socialcast::CommandLine::Provisioner
      def sync
        @ldap_config['connections'].keys.each do |connection_name|
          LDAPConnector.attribute_mappings_for(connection_name, @ldap_config).fetch(LDAPConnector::PROFILE_PHOTO_ATTRIBUTE)
        end

        each_ldap_connector do |connector|
          connector.each_photo_hash do |photo_hash|
            email = photo_hash[LDAPConnector::EMAIL_ATTRIBUTE]

            ## GET USER INFO
            search_users_resource = Socialcast::CommandLine.resource_for_path '/api/users/search', http_config
            user_search_response = search_users_resource.get(:params => { :q => email, :per_page => 1 }, :accept => :json)
            user_info = JSON.parse(user_search_response)['users'].first

            is_community_default = user_info && user_info['avatars'] && user_info['avatars']['is_community_default']
            return unless is_community_default || @options[:force_sync]

            ## PHOTO URL TO BINARY
            if profile_photo_data = photo_hash[LDAPConnector::PROFILE_PHOTO_ATTRIBUTE]
              if profile_photo_data.start_with?('http')
                begin
                  profile_photo_data = RestClient.get(profile_photo_data)
                rescue => e
                  puts "Unable to download photo #{profile_photo_data} for #{email}"
                  puts e.response
                  next
                end
              end

              ## FORCE ENCODING
              profile_photo_data = profile_photo_data.force_encoding('binary')

              ## CONTENT TYPE
              unless content_type = binary_to_content_type(profile_photo_data)
                puts "Skipping photo for #{email}: unknown image format (supports .gif, .png, .jpg)"
                next
              end

              ## WRITE TEMP FILE
              tempfile = Tempfile.new(["photo_upload", ".#{content_type}"])
              tempfile.write(profile_photo_data)
              tempfile.rewind

              puts "Uploading photo for #{email}"

              ## SUBMIT PHOTO
              begin
                user_resource = Socialcast::CommandLine.resource_for_path "/api/users/#{user_info['id']}", http_config
                user_resource.put({ :user => { :profile_photo => { :data => tempfile } } })
              ensure
                tempfile.unlink
              end
            end
          end
        end
      end

      private

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
