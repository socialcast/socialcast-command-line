require 'spec_helper'

describe Socialcast::CLI do

  describe '#provision' do
    context 'with test ldap.yml config' do
      Socialcast::CLI.start ['provision', '-c', 'spec/fixtures/ldap.yml']
    end
    it 'should do stuff'
  end
end
