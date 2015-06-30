[![Build Status](https://secure.travis-ci.org/socialcast/socialcast-command-line.png?branch=master)](http://travis-ci.org/socialcast/socialcast-command-line)
# socialcast-command-line

## Purpose
Used as a command line interface to interact with the Socialcast API
http://www.socialcast.com/resources/api.html

## Installing

1. Run: `gem install socialcast`
2. Authenticate: `socialcast authenticate`
	* If your account is private cloud or On-Premise you will need to use `socialcast authenticate --domain YOUR_DOMAIN_NAME`

## Available Commands
### socialcast info
Used to tell you information about the currently installed gem.

> Example `$ socialcast -v`

### socialcast authenticate
Used to authenticate your local system to the Socialcast servers. This will create a credentials file stored locally that will be later used to send secure, authenticated requests to Socialcast.
> Example `$ socialcast authenticate --domain demo.socialcast.com`

### socialcast authenticate&#95;external&#95;system
Similar to the `socialcast authenticate` command listed above but will allow you to use a provisioning system to authenticate against Socialcast.

> Example `$ socialcast authenticate_external_system --domain demo.socialcast.com`

*Note: Using an external system is currently limited to the provisioning endpoint*

### socialcast share
Used to post a message to the stream as the currently authenticated person.
> Example `$ socialcast share 'Hi Team!'`

### socialcast provision
Used to sync an LDAP server with your Socialcast community.

[For more detailed information](http://developers.socialcast.com/admin/directory-integration-overview/)

> Example `$ socialcast provision --config /path/to/ldap.yml`

### socialcast sync&#95;photos
Used to sync an employees photos stored in LDAP with their Socialcast
profile photo.

> Example `$ socialcast sync_photos --config /path/to/ldap.yml`

## Contributing

* Fork the project.
* Fix the issue
* Add tests
* Send me a pull request. Bonus points for topic branches.

See [CONTRIBUTORS.txt](https://github.com/socialcast/socialcast-command-line/blob/master/CONTRIBUTORS.txt) for list of contributors

## Copyright

Copyright (c) 2011 - 2015 VMware Inc.
See [LICENSE.txt](https://github.com/socialcast/socialcast-command-line/blob/master/LICENSE.txt) for details.
