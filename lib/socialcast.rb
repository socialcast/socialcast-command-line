module Socialcast
  def config_dir
    config_dir = File.expand_path '~/.socialcast'
    FileUtils.mkdir config_dir, :mode => 0700 unless File.exist?(config_dir)
    config_dir
  end
  def credentials_file
    File.join config_dir, 'credentials.yml'
  end
  def save_credentials(options)
    File.open(credentials_file, "w") do |f|
      f.write(options.to_yaml)
    end
    File.chmod 0600, credentials_file
  end
  def credentials
    raise 'Unknown Socialcast credentials.  Run `socialcast authenticate` to initialize' unless File.exist?(credentials_file)
    YAML.load_file(credentials_file)
  end
end
