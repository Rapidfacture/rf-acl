/**
 * get session secret from db
 * acl: check if req route is allowed as express middelware
 * decrypt token an put rights object in req
 */


var jwt = require('jsonwebtoken'),
   async = require('async'),
   NodeCache = require('node-cache'),
   myCache = new NodeCache({
      stdTTL: 10,
      checkperiod: 4
   }),
   config = require('rf-config'),
   _ = require('lodash');


   // logging
var log = {
   info: console.log,
   success: console.log,
   error: console.error,
   critical: function () {
      throw new Error(console.error.apply(arguments));
   }
};
try { // try using rf-log
   log = require(require.resolve('rf-log')).customPrefixLogger('[rf-api-acl]');
} catch (e) {}



module.exports.start = function (options, next) {

   if (!options) log.critical('"options" is undefined');
   if (!options.API) log.critical('"options.API" is undefined');
   if (!options.sessionSecret) log.critical('"options.sessionSecret" is undefined');
   if (!options.app) log.critical('"options.app" is undefined');
   if (!options.db) log.critical('"options.db" is undefined');

   var API = options.API;
   var sessionSecret = options.sessionSecret;
   var app = options.app;
   var db = options.db;

   startACL(sessionSecret);


   function startACL (sessionSecret) {
      // Add token processing functions for applications not using express
      // Returns a Promise of userInfo
      /**
       * Verify if a given token is correct in the current context
       */
      function verifyToken (token) {
         // Prevent unreadable jwt must be provided
         if (_.isNil(token) || token === '') {
            return Promise.reject(new Error('Token is null, undefined or empty'));
         }
         // Actually process token
         return new Promise((resolve, reject) => {
            jwt.verify(token, sessionSecret, { ignoreExpiration: false }, (err, decoded) => {
               if (err) {
                  return reject(err);
               } else {
                  return resolve(decoded);
               }
            });
         });
      }

      /*
      websocket.use(function () {

      })
      */


      /**
       * NOTE: this function is used by rf-api-websocket only
       *
       * Check if the current token allows the ACL to take place
       * Returns a Promise that:
       *    - resolves with an info object if permitted
       *    - rejects if not permitted
       *
       */
      function checkACL (token, acl) {
         // TODO proper implementation
         return verifyToken(token).then(decodedToken => {
            // TODO actually verify something. Currently this will accept in any case
            // NOTE: any exception will reject
            // if(acl.section == ...) {...} else {throw new Exception("Not authorized");}
            return getSession(token).then(session => {
               return {
                  session: session,
                  token: token,
                  decoded: decodedToken,
                  tokenValid: true,
                  rights: session.rights,
                  user: session.user
               };
            });
         }).catch(err => {
            // If ACL is empty, this is not considered an error
            if (_.isEmpty(acl)) {
               return {}; // No error, return empty user object
            }
            // Else: This is an error, reject the promise
            throw err;
         });
      }
      // Register services
      API.Services.registerFunction(verifyToken);
      API.Services.registerFunction(checkACL);

      function getSession (token, res = null) {
         return new Promise((resolve, reject) => {
            async.waterfall([
               loadFromCache,
               loadFromDB,
               saveToCache
            ], function (err, session) {
               if (err) {
                  reject(err);
               } else {
                  resolve(session);
               }
            });

            function loadFromCache (callback) {
               // session with key "token" in cache?
               myCache.get(token, callback);
            }

            function loadFromDB (session, callback) {
               // not in cache => get from db
               if (!session) {
                  db.user.sessions
                     .findOne({
                        'token': token
                     })
                     .exec(function (err, session) {
                        if (err || !session) {
                           callback(err || 'No session found!');
                        } else {
                           callback(null, session);
                        }
                     });
               } else {
                  callback(null, session);
               }
            }

            function saveToCache (session, callback) {
               // put in cache but do not wait for it
               myCache.set(token, session, function () {});
               callback(null, session);
            }
         });
      }

      // process the token
      app.use(function (req, res, next) {
         // check for token
         var token = req.body.token || req.query.token || req.headers['x-access-token'];

         if (token) {
            req._token = token;
            async.waterfall([
               function (callback) {
                  verifyToken(token).then(decoded => {
                     req._decoded = decoded;
                     req._tokenValid = true;
                     callback(null);
                  }).catch(err => {
                     log.error(`Bad token: ${err}`);
                     req._decoded = null;
                     req._tokenValid = false;
                     callback(null);
                  });
               },
               function (callback) {
                  getSession(token, res)
                     .then(function (session) {
                        req._session = session;
                        callback(null);
                     })
                     .catch(function (err) {
                        req._session = null;
                        callback(err);
                     });
               }
            ], function (err, session) {
               if (err) {
                  log.error(err);
                  res.status(401).send(err); // send internal server error
               } else {
                  next();
               }
            });
         // no token
         } else {
            next();
         }
      });

      function getBasicConfig (token, callback) {
         var loginUrls = config.global.apps['rf-app-login'].urls;
         var basicInfo = {
            app: config.app,
            loginUrl: loginUrls.main + loginUrls.login,
            loginMainUrl: loginUrls.main,
            termsAndPolicyLink: loginUrls.termsAndPolicyLink
         };

         // console.log('req.body', req.body);

         if (token) {
            return getSession(token)
               .then(function (session) {

                  session = session.toObject();

                  delete session.browserInfo; // only interesting for statistic, no need in client
                  delete session.groups; // groups should not be passed
                  delete session.user.groups; // groups should not be passed

                  for (var key in session) {
                     basicInfo[key] = session[key];
                  }
                  // console.log('basicInfo after session get', basicInfo);
                  callback(basicInfo);
               })
               .catch(function (err) {
                  log.error(err);
                  callback(basicInfo);
               });
         } else {
            return callback(basicInfo);
         }
      }

      /** /basic-config
       *
       * provide the frontend config
       *
       * # info without token:
       * login url
       * app information
       *
       * # info with token
       * data from session
       */
      app.post('/basic-config', function (req, res) {
         // console.log('/basic-config');
         var token = (req.body && req.body.token) ? req.body.token : null;
         getBasicConfig(token, function (basicConfig) {
            res.status(200).send(basicConfig).end();
         });
      });

      log.success('Session started');

      if (next) next();
   }

};
