# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "socialcast/version"

Gem::Specification.new do |s|
  s.name        = "socialcast"
  s.version     = Socialcast::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Ryan Sonnek","Sean Cashin"]
  s.email       = ["ryan@socialcast.com"]
  s.homepage    = "http://github.com/wireframe/socialcast-command-line"
  s.summary     = %q{command line interface to socialcast api}
  s.description = %q{publish messages to your stream from a command line interface}

  s.rubyforge_project = "socialcast"
  
  s.add_runtime_dependency 'rest-client', '>= 1.4.0'
  s.add_runtime_dependency 'json', '>= 1.4.6'
  s.add_runtime_dependency 'thor', '>= 0.14.6'
  s.add_runtime_dependency 'highline', '>= 1.6.2'
  s.add_runtime_dependency 'socialcast-net-ldap', '>= 0.1.6'
  s.add_runtime_dependency 'activeresource', '>= 2.3.11'
  s.add_development_dependency "rspec", '>= 2.6.0'
  s.add_development_dependency "webmock", '>= 1.7.7'
  s.add_development_dependency 'rake', '0.9.2.2'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
end
