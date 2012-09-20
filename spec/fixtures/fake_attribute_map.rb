module Socialcast
  class FakeAttributeMap
    def self.run(entry)
      return "#{entry[:mail].first.gsub(/a/,'b')}"
    end
  end
end
