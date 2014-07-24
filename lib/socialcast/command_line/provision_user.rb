require 'zlib'
require 'builder'
require 'set'
require 'fileutils'

module Socialcast
  module CommandLine
    class ProvisionUser
      include Socialcast::CommandLine::Provisioner

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
        user_whitelist = Set.new
        output_file = File.join Dir.pwd, @options[:output]
        params = http_config.merge(:external_system => !!@options[:external_system])

        Zlib::GzipWriter.open(output_file) do |gz|
          xml = Builder::XmlMarkup.new(:target => gz, :indent => 1)
          xml.instruct!
          xml.export do |export|
            export.users(:type => "array") do |users|
              each_user_hash do |user_hash|
                users << user_hash.to_xml(:skip_instruct => true, :root => 'user')
                user_whitelist << [user_hash['contact_info'][LDAPConnector::EMAIL_ATTRIBUTE], user_hash[LDAPConnector::UNIQUE_IDENTIFIER_ATTRIBUTE], user_hash['employee_number']]
              end
            end # users
          end # export
        end # gzip

        if user_whitelist.empty? && !@options[:force]
          raise ProvisionError.new "Skipping upload to Socialcast since no users were found"
        else
          log "Uploading dataset to Socialcast..."
          resource = Socialcast::CommandLine.resource_for_path '/api/users/provision', params
          begin
            File.open(output_file, 'r') do |file|
              request_params = {:file => file}
              request_params[:skip_emails] = 'true' if (@ldap_config.fetch('options', {})["skip_emails"] || @options[:skip_emails])
              request_params[:test] = 'true' if (@ldap_config.fetch('options', {})["test"] || @options[:test])
              request_params[:add_only] = 'true' if (@ldap_config.fetch('options', {})['add_only'] || @options[:add_only])
              resource.post request_params, :accept => :json
            end
          rescue RestClient::Unauthorized => e
            raise ProvisionError.new "Authenticated user either does not have administration privileges or the community is not configured to allow provisioning. Please contact Socialcast support to if you need help." if e.http_code == 401
          end
          log "Finished"
        end
        File.delete(output_file) if (@ldap_config.fetch('options', {})['delete_users_file'] || @options[:delete_users_file])
      end
    end
  end
end
