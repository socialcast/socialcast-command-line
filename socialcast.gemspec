# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "socialcast/command_line/version"

Gem::Specification.new do |s|
  s.name        = "socialcast"
  s.version     = Socialcast::CommandLine::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Ryan Sonnek","Sean Cashin","Lars Klevan"]
  s.email       = ["sean@socialcast.com"]
  s.homepage    = "http://github.com/socialcast/socialcast-command-line"
  s.summary     = %q{command line interface to socialcast api}
  s.description = %q{publish messages to your stream from a command line interface}
  s.license     = 'MIT'

  s.rubyforge_project = "socialcast"

  s.add_runtime_dependency 'rest-client', '~> 1.7'
  s.add_runtime_dependency 'json', '~> 1.4', '>= 1.4.6'
  s.add_runtime_dependency 'thor', '~> 0.14', '>= 0.14.6'
  s.add_runtime_dependency 'highline', '~> 1.6', '>= 1.6.2'
  s.add_runtime_dependency 'socialcast-net-ldap', '~> 0.1', '>= 0.1.6'
  s.add_runtime_dependency 'activeresource', '~> 4.0'
  s.add_runtime_dependency 'activesupport', '~> 4.0'
  s.add_development_dependency 'rspec', '~> 3.3'
  s.add_development_dependency 'webmock', '~> 1.7', '>= 1.7.7'
  s.add_development_dependency 'rake', '0.9.2.2'
  s.add_development_dependency 'pry', '~> 0.9'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
end
