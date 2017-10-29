/**
 * get session secret from db
 * acl: check if req route is allowed as express middelware
 * decrypt token an put rights object in req
 */


var // jwt = require('jsonwebtoken'),
   NodeCache = require('node-cache'),
   myCache = new NodeCache({
      stdTTL: 1000,
      checkperiod: 250
   }),
   os = require('os'),
   config = require('rf-config'),
   log = require('rf-log'),
   db = require('rf-load').require('db').db,
   app = require('rf-load').require('http').app



// get internal ip addresses for allowing internal requests
var interfaces = os.networkInterfaces()
var internalIpAddresses = []
for (var k in interfaces) {
   for (var k2 in interfaces[k]) {
      var address = interfaces[k][k2]
      internalIpAddresses.push(address.address.replace('::ffff:', ''))
   }
}


module.exports.start = function (options, startNextModule) {
   // get session secret from db
   db.global.settings.findOne({
      name: 'sessionSecret'
   }, function (err, doc) {
      var sessionSecret
      if (err) log.critical(err)
      if (doc && doc.settings && doc.settings.value) {
         sessionSecret = doc.settings.value
      } else {
         // no secret => create one and put it in db (avalibale for other apps)
         log.info("Couldn't load session secret, creating a new one")
         sessionSecret = require('crypto').randomBytes(64).toString('hex')

         db.global.mongooseConnection.collection('settings').insert({
            name: 'sessionSecret',
            settings: {
               value: sessionSecret
            }
         })
      }
      config.sessionSecret = sessionSecret // login function als needs it
      startACL(sessionSecret)
   })


   function startACL (sessionSecret) {
      // process the token
      app.use(function (req, res, next) {
         // check for token
         var token = req.body.token || req.query.token || req.headers['x-access-token']

         if (token) {
            try {
               getSession(token, res, function (session) {
                  // make data accessible afterwards
                  req._session = session
                  req._token = token
                  // req._decoded = jwt.verify(token, sessionSecret, {
                  //    ignoreExpiration: true
                  // });
                  next()
               })
            } catch (err) {
               error()
            }

         // no token
         } else {
            next()
         }

         function error () {
            res.status(403).send('AuthenticateFailed')
         }


         function getSession (token, res, next) {
            // session with key "token" in cach?
            myCache.get(token, function (err, session) {
               if (err) {
                  log.error('node-cache ', err)
               } else {
                  // not in cache => get from db and put in cache
                  if (session === undefined || session === null) {
                     db.user.sessions.findOne({
                        'token': token
                     })
                        .populate({
                           path: 'user',
                           populate: {
                              path: 'account'
                           }
                        })
                        .exec(function (err, doc) {
                           if (err) log.critical(err)
                           if (doc) {
                              session = doc
                              myCache.set(token, session, function (err, success) {
                                 if (err) {
                                    log.error('node-cache ', err)
                                 } else {
                                    // console.log("session from db", session);
                                    next(session)
                                 }
                              })

                           // no session found in db
                           } else {
                              error()
                           }
                        })

                     // return session from cache
                  } else {
                     // console.log("session in cache", session);
                     next(session)
                  }
               }
            })
         }
      })


      // check if rout allowed
      app.use(function (req, res, next) {
         // Do not protect internal requests
         var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress
         ip = ip.replace('::ffff:', '')

         // console.log(req._session);

         if (internalIpAddresses.indexOf(ip) < 0) {
            if (!config.acl) {
               log.warning('No acls found in config! Nothing is protected!')
               next()
            } else {
               for (var c in config.acl) {
                  if (req.url.match(new RegExp(c, 'g'))) {
                     // protected
                     if (config.acl[c] !== false) {
                        // req._session
                        // req._token

                        // TODO
                        // Check for roles for this route
                        // if (decoded.roles.indexOf(config.acl[c]) < 0) {
                        //    return res.status(403).json({
                        //       success: false,
                        //       message: 'Wrong permissions.'
                        //    }, 403);
                        // }

                        // everything good
                        next()
                     } else { // no token => error
                        next()

                        // return res.status(403).json({
                        //    success: false,
                        //    message: 'No token provided.'
                        // }, 403);
                     }

                  // unprotected
                  } else {
                     next()
                  }
               }
            }
         // internal
         } else {
            next()
         }
      })


      // provide the login url (no acl here)
      app.post('/basic-config', function (req, res) {
         var loginUrls = config.global.apps.login.urls
         var basicInfo = {
            app: config.app,
            loginUrl: loginUrls.main + loginUrls.login,
            loginMainUrl: loginUrls.main
         }
         res.status(200).send(basicInfo).end()
      })


      log.success('Session started')
      startNextModule()
   }
}
