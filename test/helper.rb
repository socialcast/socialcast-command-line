require 'rubygems'
require 'test/unit'
require 'shoulda'
require File.join(File.dirname(__FILE__), 'commander_helper')

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'socialcast'

class Test::Unit::TestCase
end
