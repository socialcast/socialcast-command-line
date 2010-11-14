require File.join(File.dirname(__FILE__), 'helper')
load File.join(File.dirname(__FILE__), '..', 'bin', 'socialcast')

class TestSocialcast < Test::Unit::TestCase
  context 'socialcast command' do
    setup do
      command(:share).run
    end
    should 'run' do
    end
  end
end
