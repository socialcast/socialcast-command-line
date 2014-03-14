module Socialcast
  module CommandLine
    class FakeAttributeMap
      def self.attributes
        %w{plugin_attr}
      end
      def self.run(entry)
        return "#{entry[:plugin_attr].first.gsub(/a/,'b')}"
      end
    end
  end
end
