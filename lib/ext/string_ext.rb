if RUBY_VERSION < '1.9.2'
  class String
    old_format = instance_method(:%)

    define_method(:%) do |arg|
      if arg.is_a?(Hash)
        self.gsub(/%\{(.*?)\}/) { arg[$1.to_sym] }
      else
        old_format.bind(self).call(arg)
      end
    end
  end
end