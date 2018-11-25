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


let sessionSecret = null;
let db = null;


module.exports = {

   start: function (options) {
      if (!options) log.critical('"options" is undefined');
      if (!options.sessionSecret) log.critical('"options.sessionSecret" is undefined');
      if (!options.db) log.critical('"options.db" is undefined');

      sessionSecret = options.sessionSecret;
      db = options.db;

      log.success('Session started');
   },



   /**
    * Verify if a given token is correct in the current context
    */
   verifyToken: function (token) {
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
   },


   getSession: function (token, res = null) {
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
   },


   verifyTokenAndGetSession: function (token, mainCallback) {
      module.exports.verifyToken(token).then(decoded => {
         module.exports.getSession(token)
            .then(function (session) {
               session = session.toObject();
               delete session.browserInfo; // only interesting for statistic, no need in client
               delete session.groups; // groups should not be passed
               delete session.user.groups; // groups should not be passed
               mainCallback({err: null, decoded: decoded, session: session});
            })
            .catch(function (err) {
               log.error(err);
               mainCallback({err: err, decoded: decoded});
            });
      }).catch(err => {
         // verify error
         log.error(`Bad token: ${err}`);
         mainCallback({err: err});
      });
   },


   processRequest: function (settings, req, callback) {

      // protection => no one misses to add the protection explicit
      if (!settings || !settings.section) {
         return callback({
            message: 'No settings defined! Protected by default',
            code: 403
         });
      }

      // token is invalid?
      if (!req.tokenValid) {
         // is there a token?
         return callback({
            message: req.token ? 'Access denied! Token expired!' : 'Access denied! Token missing!',
            code: 401
         });
      }

      // unprotected route?
      if (settings.permission === false) {
         return callback(null, req);
      }

      // has user app config rights?
      if (!req.rights || !req.rights.hasOwnProperty(config.app.name)) {
         return callback({
            message: 'Access denied!',
            code: 403
         });
      }

      var rights = req.rights[config.app.name];

      if (!rights.hasOwnProperty(settings.section)) {
         return callback({
            message: `Access denied! Section not found in rights: ${settings.section}`,
            code: 403
         });
      } else { // set section rights to request
         req.sectionRights = rights[settings.section];
      }

      var requiredPermission = (req.originalRequest.method === 'GET' ? 'read' : 'write');
      if (!rights[settings.section].hasOwnProperty(requiredPermission) ||
               rights[settings.section][requiredPermission] === false ||
               rights[settings.section][requiredPermission].length <= 0) {
         return callback({
            message: 'Access denied! Insufficient permissions!',
            code: 403
         });
      }

      callback(null, req);
   }



   // NOTE:
   // API and app are no longer required and are no longer exposed over "API.Service"


   // Register services
   // API.Services.registerFunction(verifyToken);
   // API.Services.registerFunction(checkACL);
   // API.Services.registerFunction(verifyTokenAndGetSession);

   /**
       * NOTE: this should ne moved to rf-api-websocket; ther eshould be also "processRequest" integrated
       *
       */
   // function checkACL (token, acl) {
   //    return verifyTokenAndGetSession(token, function (settings) {
   //       if (settings.err || !settings.decoded || !settings.session) {
   //          if (settings.err) log.error(settings.err);
   //          if (acl.section && acl.permission === false) {
   //             return {}; // No error, return empty user object
   //          } else {
   //             throw settings.err;
   //          }
   //       } else {
   //          return {
   //             session: settings.session,
   //             token: token,
   //             decoded: settings.decoded,
   //             tokenValid: true,
   //             rights: settings.session.rights,
   //             user: settings.session.user
   //          };
   //       }
   //    });
   // }


   // TODO: move the following functions into rf-api:

   // the function "processRequest" should replace the corresponding code there

   // process the token
   // app.use(function (req, res, next) {
   //
   //    // do not protect endpoint /basic-config
   //    if (req.originalUrl === '/basic-config') return next();
   //
   //    // check for token
   //    var token = req.body.token || req.query.token || req.headers['x-access-token'];
   //
   //    if (token) {
   //       req._token = token;
   //       verifyTokenAndGetSession(token, function (settings) {
   //          if (settings.err) log.error(settings.err);
   //          req._decoded = settings.decoded ? settings.decoded : null;
   //          req._tokenValid = !!settings.decoded;
   //          req._session = settings.session ? settings.session : null;
   //          next();
   //       });
   //    // no token
   //    } else {
   //       next();
   //    }
   // });


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
   // app.post('/basic-config', function (req, res) {
   //    // console.log('/basic-config');
   //    var token = (req.body && req.body.token) ? req.body.token : null;
   //    getBasicConfig(token, function (err, basicConfig) {
   //       if (err) {
   //          basicConfig.err = err;
   //          res.status(400).send(basicConfig).end();
   //       } else {
   //          res.status(200).send(basicConfig).end();
   //       }
   //
   //    });
   // });
   //
   // function getBasicConfig (token, mainCallback) {
   //    var loginUrls = config.global.apps['rf-app-login'].urls;
   //    var basicInfo = {
   //       app: config.app,
   //       loginUrl: loginUrls.main + loginUrls.login,
   //       loginMainUrl: loginUrls.main,
   //       termsAndPolicyLink: loginUrls.termsAndPolicyLink
   //    };
   //    // console.log('req.body', req.body);
   //
   //    if (token) {
   //       verifyTokenAndGetSession(token, function (settings) {
   //          if (settings.err) log.error(settings.err);
   //          if (settings.session) {
   //             for (var key in settings.session) {
   //                basicInfo[key] = settings.session[key];
   //             }
   //          }
   //          mainCallback(null, basicInfo);
   //       });
   //    } else {
   //       return mainCallback(null, basicInfo);
   //    }
   // }



};
