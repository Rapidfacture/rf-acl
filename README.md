# rf-load

* This is a somewhat specific module for internal RapidFacture usage, that may not be sufficiently generalized to be suitable for anyone else
* NodeJS module for user access, OAuth and passport control as well as authorization checks
* Dependencies: rf-log, rf-load, the db module, bcrypt-nodejs
   * When passport is used: passport
   * When login functionality is enabled: passport-local
   * When OAuth server is used: oauth2orize, passport-http, passport-oauth2-client-password, passport-http-bearer

## Getting Started

> npm install rf-acl

Initialize passport WITHOUT using rf-load as follows:

```js
const express = require("express"),
   acl = require("rf-acl");
const app = express();

acl.start({
   express: app, // Provide express
   initPassport: true, // Init Passport to allow for user state access
   initLogin: true, // Init Passport-local to allow user authorization
   initOAuthServer: true, // Init OAuth server
});
```

If you are using rf-load anyway in your main program, this could look slightly different:

```js
var load = new(require("rf-load").moduleLoader)();

load.file("db");
load.file("http");
// ...
load.module("rf-acl", {
   express: load.require("http").app, // Provide express
   initPassport: true, // Init Passport to allow for user state access
   initLogin: true, // Init Passport-local to allow user authorization
   initOAuthServer: true, // Init OAuth server
});
```

## User retrieval from database

To retrieve a user from the database, you can either search by username or by profileId. Also you can retrieve the user profile:

```js
acl.findById(123, function (err, user) {
   if (err || typeof user !== "object") {
      console.log("Oh no! " + err);
      return;
   }

   // ...
});
acl.findByUsername("fred", function (err, user) {
   if (err || typeof user !== "object") {
      console.log("Oh no! " + err);
      return;
   }

   acl.findProfileById(user.profileId, function (err, profile) {
      if (err || typeof profile !== "object") {
         console.log("Oh no! " + err);
         return;
      }

      // ...
   });
});
```

## Legal Issues
* Licenese: MIT
* Author: Julian von Mendel
