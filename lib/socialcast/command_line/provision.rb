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
        each_ldap_connector do |connector|
          connector.each_user_hash do |user_hash|
            yield user_hash
          end
        end
      end

      def fetch_user_hash(identifier, options = {})
        each_ldap_connector do |connector|
          user_hash = connector.fetch_user_hash(identifier, options)
          return user_hash if user_hash
        end
        nil
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

        if user_whitelist.empty? && !@options[:force]
          raise ProvisionError.new "Skipping upload to Socialcast since no users were found"
        else
          puts "Uploading dataset to Socialcast..."
          resource = Socialcast::CommandLine.resource_for_path '/api/users/provision', http_config
          begin
            File.open(output_file, 'r') do |file|
              request_params = {:file => file}
              request_params[:skip_emails] = 'true' if (@ldap_config.fetch('options', {})["skip_emails"] || @options[:skip_emails])
              request_params[:test] = 'true' if (@ldap_config.fetch('options', {})["test"] || @options[:test])
              resource.post request_params, :accept => :json
            end
          rescue RestClient::Unauthorized => e
            raise ProvisionError.new "Authenticated user either does not have administration privileges or the community is not configured to allow provisioning. Please contact Socialcast support to if you need help." if e.http_code == 401
          end
          puts "Finished"
        end
        File.delete(output_file) if (@ldap_config.fetch('options', {})['delete_users_file'] || @options[:delete_users_file])
      end

      def sync_photos
        http_config = @ldap_config.fetch 'http', {}

        each_ldap_connector do |connector|
          connector.attribute_mappings.fetch('profile_photo')
        end

        search_users_resource = Socialcast::CommandLine.resource_for_path '/api/users/search', http_config

        each_ldap_connector do |connector|
          each_ldap_entry do |entry|
            attr_mappings = connector.attribute_mappings
            email = connector.grab(entry, attr_mappings['email'])
            if profile_photo_data = connector.grab(entry, attr_mappings['profile_photo'])
              if profile_photo_data.start_with?('http')
                begin
                  profile_photo_data = RestClient.get(profile_photo_data)
                rescue => e
                  puts "Unable to download photo #{profile_photo_data} for #{email}"
                  puts e.response
                  next
                end
              end
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
      end

      private

      def ldap_connector(connection_name)
        @connectors ||= {}

        unless @connectors[connection_name]
          @connectors[connection_name] = Socialcast::CommandLine::LDAPConnector.new(connection_name, @ldap_config)
        end

        @connectors[connection_name]
      end

      def each_ldap_connector
        @ldap_config['connections'].keys.each do |connection_name|
          yield ldap_connector(connection_name)
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
