# rf-acl

ACL Module for Rapidfacture Apps
* fetches session secret from db
* fetches session (user, groups, right) of the users and stores them in memory
* provide "basic-config" Acess Point



## Getting Started

> npm install rf-acl


```js

// prepare backend
var config = require('rf-config').init(__dirname); // config
var http = require('rf-http').start({ // webserver
   pathsWebserver: config.paths.webserver,
   port: config.port
});
var API = require('rf-api').start({app: http.app}); // prepare api
var mongooseMulti = require('mongoose-multi'); // databases
var db = mongooseMulti.start(config.db.urls, config.paths.schemas);


// fetch settings from db
db.global.mongooseConnection.once('open', function () {

   // start access control
   require('rf-acl').start({
      API: API, // rf-api
      db: db, // mongooseMulti
      app: http.app, // express app
      sessionSecret: 'dsafdknewr324324erd3uidecd'
   });

   // start requests
   API.startApiFiles(config.paths.apis, function (startApi) {
      startApi(db, API);
   });
});


```


## Peer Dependencies
* rf-config


## Development
Install the dev tools with

> npm install

Then you can runs some test cases and eslint with:

> npm test


## Legal Issues
* License: MIT
* Author: Rapidfacture GmbH
