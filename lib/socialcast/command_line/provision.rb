require 'zlib'
require 'builder'
require 'set'
require 'fileutils'
require 'socialcast/command_line/ldap_connector'

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

        if @options[:sanity_check]
          puts "Sanity checking users currently marked as needing to be terminated"
          each_ldap_connector do |connector|
            attr_mappings = connector.attribute_mappings
            (current_socialcast_users(http_config) - user_whitelist).each do |user_identifiers|
              combined_filters = []
              ['email', 'unique_identifier', 'employee_number'].each_with_index do |identifier, index|
                combined_filters << ((attr_mappings[identifier].blank? || user_identifiers[index].nil?) ? nil : Net::LDAP::Filter.eq(attr_mappings[identifier], user_identifiers[index]))
              end
              combined_filters.compact!
              filter = ((combined_filters.size > 1) ? '(|%s)' : '%s') % combined_filters.join(' ')
              filter = Net::LDAP::Filter.construct(filter) & Net::LDAP::Filter.construct(connector.connection_config["filter"])
              ldap_result = connector.ldap.search(:return_result => true, :base => connector.connection_config["basedn"], :filter => filter, :attributes => connector.ldap_search_attributes)
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
    end
  end
end
