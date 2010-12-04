require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "socialcast"
    gem.summary = %Q{command line interface to socialcast api}
    gem.description = %Q{publish messages to your stream from a command line interface}
    gem.email = "ryan@socialcast.com"
    gem.homepage = "http://github.com/wireframe/socialcast-command-line"
    gem.authors = ["Ryan Sonnek"]
    gem.add_development_dependency "shoulda", ">= 0"
    gem.add_runtime_dependency 'commander', '>= 4.0'
    gem.add_runtime_dependency 'rest-client', '>= 1.4.0'
    gem.add_runtime_dependency 'json', '>= 1.4.6'
    # gem is a Gem::Specification... see http://www.rubygems.org/read/chapter/20 for additional settings
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: gem install jeweler"
end

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end

begin
  require 'rcov/rcovtask'
  Rcov::RcovTask.new do |test|
    test.libs << 'test'
    test.pattern = 'test/**/test_*.rb'
    test.verbose = true
  end
rescue LoadError
  task :rcov do
    abort "RCov is not available. In order to run rcov, you must: sudo gem install spicycode-rcov"
  end
end

task :test => :check_dependencies

task :default => :test

require 'rake/rdoctask'
Rake::RDocTask.new do |rdoc|
  version = File.exist?('VERSION') ? File.read('VERSION') : ""

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "socialcast_cli #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
