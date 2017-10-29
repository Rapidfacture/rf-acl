# rf-acl

* ACL Module for Rapidfacture Apps
* beware: in Alpha!
* started via rf-load module Loader; needs also other rf-modules as peer Dependencies
* fetches session secret from db or creates one
* fetches session (user, groups, right) of the users and stores them in memory



## Getting Started

> npm install rf-acl


```js
var Loader = require('rf-load').moduleLoader
var load = new Loader()
load.setModulePath(config.paths.modules)

// load db, start webserver (required for the ACL)
load.file('db')
load.file('http')


// load access control module
load.module('rf-acl')


// load further module like the request API ...
```


## Peer Dependencies
* rf-log
* rf-config
* rf-load

Database for rapidfacture apps + express module


## Development
Install the dev tools with

> npm install

Then you can runs some test cases and eslint with:

> npm test


## Legal Issues
* License: MIT
* Author: Rapidfacture GmbH
