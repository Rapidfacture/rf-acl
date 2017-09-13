// rf-acl configures passport, the OAuth server, provides functions for user
// access in database and does authorization checks
/* jshint node: true, esversion:6 */ "use strict";

const log = require("rf-log"),
   bcrypt = require('bcrypt-nodejs'),
   db = require("rf-load").require("db").db;
let passport = null;

module.exports.start = function (options, next) {
   if (options.initPassport && options.express) {
      passport = require('passport');

      options.express.use(passport.initialize());
      options.express.use(passport.session());

      passport.serializeUser((user, done) => done(null, user.profileId));

      passport.deserializeUser((id, done) => {
        done(null, { profileId: id });
        //module.exports.findById(profileId, (error, user) => done(error, user));
      });
   }

   if (options.initPassport && options.initLogin) {
      module.exports.initializePassportLogin();
   }

   if (options.initPassport && options.initOAuthServer) {
      module.exports.initializeOAuthServer();
   }

   if (typeof next === "function") {
      next();
   }
};

module.exports.initializePassportLogin = function () {
   const LocalStrategy = require('passport-local').Strategy;

   /**
    * LocalStrategy
    *
    * This strategy is used to authenticate users based on a username and password.
    * Anytime a request is made to authorize an application, we must ensure that
    * a user is logged in before asking them to approve the request.
    */
   passport.use(new LocalStrategy(
     (username, password, done) => {
       log.info("email: " + username + " password: " + password);
       module.exports.findByUsername(username, (error, user) => {
         //if (error) return done(error);
         if (error || !user) return done(null, false);
         module.exports.validatePassword(password, user.password,
           function (err, res) {
              if (!res) {
                 return done(null, false);
              }
              return done(null, user);
           });
       });
     }
   ));
};

module.exports.oauthServer = null;
module.exports.initializeOAuthServer = function () {
   const BasicStrategy = require('passport-http').BasicStrategy,
      ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy,
      BearerStrategy = require('passport-http-bearer').Strategy,
      oauth2orize = require('oauth2orize');

   /**
    * Return a unique identifier with the given `len`.
    *
    * @param {Number} length
    * @return {String}
    */
   function getUid(length) {
     let uid = '';
     const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

     for (let i = 0; i < length; ++i) {
       uid += chars[Math.floor(Math.random() * chars.length)];
     }

     return uid;
   }

   // Create OAuth 2.0 server
   const server = oauth2orize.createServer();
   module.exports.oauthServer = server;

   // Register serialialization and deserialization functions.
   //
   // When a client redirects a user to user authorization endpoint, an
   // authorization transaction is initiated. To complete the transaction, the
   // user must authenticate and approve the authorization request. Because this
   // may involve multiple HTTP request/response exchanges, the transaction is
   // stored in the session.
   //
   // An application must supply serialization functions, which determine how the
   // client object is serialized into the session. Typically this will be a
   // simple matter of serializing the client's ID, and deserializing by finding
   // the client by ID from the database.

   server.serializeClient((client, done) => done(null, client.id));

   server.deserializeClient((id, done) => {
     module.exports.findClientById(id, (error, client) => {
       if (error) return done(error);
       return done(null, client);
     });
   });

   // Register supported grant types.
   //
   // OAuth 2.0 specifies a framework that allows users to grant client
   // applications limited access to their protected resources. It does this
   // through a process of the user granting access, and the client exchanging
   // the grant for an access token.

   // Grant authorization codes. The callback takes the `client` requesting
   // authorization, the `redirectUri` (which is used as a verifier in the
   // subsequent exchange), the authenticated `user` granting access, and
   // their response, which contains approved scope, duration, etc. as parsed by
   // the application. The application issues a code, which is bound to these
   // values, and will be exchanged for an access token.

   server.grant(oauth2orize.grant.code((client, redirectUri, user, ares, done) => {
     const code = getUid(16);
     module.exports.saveAuthorizationCode(
        code, client.id, redirectUri, user.id, (error) => {
           if (error) return done(error);
           return done(null, code);
     });
   }));

   // Grant implicit authorization. The callback takes the `client` requesting
   // authorization, the authenticated `user` granting access, and
   // their response, which contains approved scope, duration, etc. as parsed by
   // the application. The application issues a token, which is bound to these
   // values.

   server.grant(oauth2orize.grant.token((client, user, ares, done) => {
     const token = getUid(256);
     module.exports.saveAccessToken(
        token, user.id, client.clientId, (error) => {
          if (error) return done(error);
          return done(null, token);
     });
   }));

   // Exchange authorization codes for access tokens. The callback accepts the
   // `client`, which is exchanging `code` and any `redirectUri` from the
   // authorization request for verification. If these values are validated, the
   // application issues an access token on behalf of the user who authorized the
   // code.

   server.exchange(oauth2orize.exchange.code((client, code, redirectUri, done) => {
     module.exports.findAuthorizationCode(code, (error, authCode) => {
       if (error) return done(error);
       if (client.id !== authCode.clientId) return done(null, false);
       if (redirectUri !== authCode.redirectUri) return done(null, false);

       const token = getUid(256);
       module.exports.saveAccessToken(
          token, authCode.userId, authCode.clientId, (error) => {
            if (error) return done(error);
            return done(null, token);
       });
     });
   }));

   // Exchange user id and password for access tokens. The callback accepts the
   // `client`, which is exchanging the user's name and password from the
   // authorization request for verification. If these values are validated, the
   // application issues an access token on behalf of the user who authorized the code.

   server.exchange(oauth2orize.exchange.password((client, username, password, scope, done) => {
     // Validate the client
     db.clients.findByClientId(client.clientId, (error, localClient) => {
       if (error) return done(error);
       if (!localClient) return done(null, false);
       if (localClient.clientSecret !== client.clientSecret) return done(null, false);
       // Validate the user
      module.exports.findByUsername(username, (error, user) => {
         if (error) return done(error);
         if (!user) return done(null, false);
         if (password !== user.password) return done(null, false);
         // Everything validated, return the token
         const token = getUid(256);
         module.exports.saveAccessToken(
            token, user.id, client.clientId, (error) => {
              if (error) return done(error);
              return done(null, token);
         });
       });
     });
   }));

   // Exchange the client id and password/secret for an access token. The callback accepts the
   // `client`, which is exchanging the client's id and password/secret from the
   // authorization request for verification. If these values are validated, the
   // application issues an access token on behalf of the client who authorized the code.

   server.exchange(oauth2orize.exchange.clientCredentials((client, scope, done) => {
     // Validate the client
     module.exports.findClientByClientId(client.clientId, (error, localClient) => {
       if (error) return done(error);
       if (!localClient) return done(null, false);
       if (localClient.clientSecret !== client.clientSecret) {
          return done(null, false);
       }

       // Everything validated, return the token
       const token = getUid(256);
       // Pass in a null for user id since there is no user with this grant type
       module.exports.saveAccessToken(
          token, null, client.clientId, (error) => {
            if (error) return done(error);
            return done(null, token);
       });
     });
   }));

   /**
    * BasicStrategy & ClientPasswordStrategy
    *
    * These strategies are used to authenticate registered OAuth clients. They are
    * employed to protect the `token` endpoint, which consumers use to obtain
    * access tokens. The OAuth 2.0 specification suggests that clients use the
    * HTTP Basic scheme to authenticate. Use of the client password strategy
    * allows clients to send the same credentials in the request body (as opposed
    * to the `Authorization` header). While this approach is not recommended by
    * the specification, in practice it is quite common.
    */
   function verifyClient(clientId, clientSecret, done) {
     module.exports.findClientByClientId(clientId, (error, client) => {
       if (error) return done(error);
       if (!client) return done(null, false);
       if (client.clientSecret !== clientSecret) return done(null, false);
       return done(null, client);
     });
   }

   passport.use(new BasicStrategy(verifyClient));

   passport.use(new ClientPasswordStrategy(verifyClient));

   /**
    * BearerStrategy
    *
    * This strategy is used to authenticate either users or clients based on an access token
    * (aka a bearer token). If a user, they must have previously authorized a client
    * application, which is issued an access token to make requests on behalf of
    * the authorizing user.
    */
   passport.use(new BearerStrategy(
     (accessToken, done) => {
       module.exports.findAccessToken(accessToken, (error, token) => {
         if (error) return done(error);
         if (!token) return done(null, false);
         if (token.userId) {
           module.exports.findByUserId(token.userId, (error, user) => {
             if (error) return done(error);
             if (!user) return done(null, false);
             // To keep this example simple, restricted scopes are not implemented,
             // and this is just for illustrative purposes.
             done(null, user, { scope: '*' });
           });
         } else {
           // The request came from a client only since userId is null,
           // therefore the client is passed back instead of a user.
           module.exports.findClientByClientId(
             token.clientId, (error, client) => {
                if (error) return done(error);
                if (!client) return done(null, false);
                // To keep this example simple, restricted scopes are not implemented,
                // and this is just for illustrative purposes.
                done(null, client, { scope: '*' });
           });
         }
       });
     }
   ));
};

// OAuth authorization code management
const codes = {};
module.exports.findAuthorizationCode = (key, done) => {
  if (codes[key]) return done(null, codes[key]);
  return done(new Error('Code Not Found'));
};
module.exports.saveAuthorizationCode =
   (code, clientId, redirectUri, userId, done) => {
     codes[code] = { clientId, redirectUri, userId };
     done();
};

// OAuth client management
/* Clients are currently hardcoded and could later on be in a database.
   They can allows apps access without additional user dialog questions.
   When we add our own apps that use OAuth, they should be listed here. */
const clients = [
  { id: '1', name: 'Samplr', clientId: 'abc123', clientSecret: 'ssh-secret', isTrusted: false },
  { id: '2', name: 'Samplr2', clientId: 'xyz123', clientSecret: 'ssh-password', isTrusted: true },
];
module.exports.findClientById = (id, done) => {
  for (let i = 0, len = clients.length; i < len; i++) {
    if (clients[i].id === id) return done(null, clients[i]);
  }
  return done(new Error('Client Not Found'));
};
module.exports.findClientByClientId = (clientId, done) => {
  for (let i = 0, len = clients.length; i < len; i++) {
    if (clients[i].clientId === clientId) return done(null, clients[i]);
  }
  return done(new Error('Client Not Found'));
};

// OAuth access token management
const tokens = {};
module.exports.findAccessToken = (key, done) => {
  if (tokens[key]) return done(null, tokens[key]);
  return done(new Error('Token Not Found'));
};
module.exports.findAccessTokenByUserIdAndClientId = (userId, clientId, done) => {
  if (Object.keys(tokens).length) {
      for (let token of tokens) {
        if (tokens[token].userId === userId && tokens[token].clientId === clientId) return done(null, token);
      }
  }
  return done(new Error('Token Not Found'));
};
module.exports.saveAccessToken = (token, userId, clientId, done) => {
  tokens[token] = { userId, clientId };
  done();
};

// Password hashing
module.exports.hashPasswordSync = function (pw) {
   var salt = bcrypt.genSaltSync(10);
   return bcrypt.hashSync(pw, salt);
};
module.exports.hashPassword = function (pw, callback) {
   bcrypt.genSalt(10, function(err, salt) {
      if (salt) {
         bcrypt.hash(pw, salt, callback);
      }
   });
};
module.exports.validatePassword = function (pw, hash, callback) {
   bcrypt.compare(pw, hash, callback);
};
module.exports.validatePasswordSync = function (pw, hash) {
   return bcrypt.compareSync(pw, hash);
};

// User database access
module.exports.findById = (id, done) => {
   /*for (let i = 0, len = user.length; i < len; i++) {
   if (user[i].id === id) return done(null, user[i]);
   }
   return done(new Error('User Not Found'));*/

   log.info("user profileId search: " + id);
   db.user.accounts
   .findOne({
      profileId: id
   })
   .exec(function(err, user) {
      if (!user) {
         return done(new Error('User Not Found'));
      } else {
         return done(null, user);
      }
   });
};

module.exports.findProfileById = (id, done) => {
   log.info("user profile search: " + id);
   db.user.profiles
   .findOne({
      _id: id
   })
   .exec(function(err, profile) {
      if (!profile) {
         return done(new Error('User Data Not Found'));
      } else {
         return done(null, profile);
      }
   });
};

module.exports.findByUsername = (username, done) => {
   /*for (let i = 0, len = user.length; i < len; i++) {
   if (user[i].username === username) return done(null, user[i]);
   }
   return done(new Error('User Not Found'));*/

   log.info("user name search: "+username);
   db.user.accounts
   .findOne({
      email: username.toLowerCase().trim()
   })
   .exec(function(err, user) {
      if (!user) {
         log.warning("user name search error: "+username);
         return done(new Error('User Not Found'));
      } else {
         log.info("user name search success: "+username);
         return done(null, user);
      }
   });
};

// Authorization control

module.exports.isGroupMember = (userdata, group) => {
   return ((Array.isArray(userdata.roles) &&
   userdata.roles.indexOf(group) != -1) ?
   true : false);
};

module.exports.settingsCheck = function (req, res, settings, done) {
   // Available settings are:
   //   * role: Verify role access
   //   * getUserData: Set to true if you want to retrieve user data,
   //       they'll be available in req.user.data
   // If user is not logged in and any of these settings are set,
   // an error code is returned.

   settings = ((typeof settings == 'object') ? settings : {});

   // If route requires user data or user role, retrieve it
   if ((settings.role || settings.getUserData) &&
         (!req.user || req.user.data === undefined)) {
      if (!req.user || !req.user.profileId) {
         res.status(401).send('Unauthorized: Not logged in').end();
         return false;
      }

      module.exports.findById(req.user.profileId, function(err, user) {
         answer(err, user, req,
            'settingsCheck user data search failed ' +
            req.user.profileId, 'docsRequired', function(err, user) {
               // save user data and jump back to beginning
               req.user.data = user;
               module.exports.settingsCheck(req, res, settings, done);
            });

         function answer(err, docs, res, functionName, docsRequired, func) {
            if (err) {
               res.status(404).send('Server Error, function ' +
                     functionName + ': ' + err).end();
               return;
            } else if (docsRequired && docs === null) {
               res.status(404).send('Server Error, function ' +
                     functionName + ': No Document found in DB').end();
            } else if (func) { // processing continues => execute when everything fine
               func(err, docs, res);
            } else { // success; last step
               res.status(200).send(docs).end();
            }
         }
      });

      // user data are still being retrieved, quit for now
      return null;
   }

   // Verify user role
   if (settings.role && !module.exports.isGroupMember(
         req.user.data, settings.role)) {
      res.status(401).send('Unauthorized: Wrong permissions').end();
      return false;
   }

   // Continue with route
   return done();
};
