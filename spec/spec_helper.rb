require 'rubygems'
require 'bundler/setup'
require 'webmock/rspec'
require 'rspec/mocks'
require 'pry'
RSpec::Mocks::setup(Object.new)

require_relative '../lib/socialcast'

RSpec.configure do |config|
  config.mock_with :rspec

  config.before do
    stubbed_credentials = File.join(File.dirname(__FILE__), '..', 'fixtures')
    Socialcast::CommandLine.stub(:config_dir).and_return(stubbed_credentials)
  end

  def capture_with_status(stream)
    exit_status = 0
    begin
      stream = stream.to_s
      eval "$#{stream} = StringIO.new"
      begin
        yield
      rescue SystemExit => system_exit # catch any exit calls
        exit_status = system_exit.status
      end
      result = eval("$#{stream}").string
    ensure
      eval("$#{stream} = #{stream.upcase}")
    end
    return result, exit_status
  end

  def remove_directories(*names)
    project_dir = Pathname.new(Dir.pwd)
    names.each do |name|
      FileUtils.rm_rf(project_dir.join(name)) if FileTest.exists?(project_dir.join(name))
    end
  end
end
