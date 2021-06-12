/*
 * Copyright (c) 2021 Privateco and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const util = require('util');

const express = require('express');
const useragent = require('express-useragent');
const SocketIOServer = require('socket.io');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const compression = require('compression');
const helmet = require('helmet');

/**
 * main entry point
 */
const main = function() {
  const app = express();
  const server = createServer(app, {
    httpsPort: 443,
    httpPort: 80,
    isHttpServerOpen: true,
    httpsCertificate: {
      key: fs.readFileSync('/etc/letsencrypt/live/clumber.cloud/privkey.pem'),
      cert: fs.readFileSync('/etc/letsencrypt/live/clumber.cloud/fullchain.pem'),
      ca: fs.readFileSync('/etc/letsencrypt/live/clumber.cloud/chain.pem'),
    },
    isDebug: false,
  });
  const transientStorage = {
    enteredSockets: new Map(),  // socket.id => credential.name
    users: new Map(),           // credential.name => credential.code
    rooms: new Map(),           // credential.code => { userCount: number, names: Set }
  };
  setUpApp(app, transientStorage);
  setUpSocketIo(server, transientStorage);
};

/**
 * Global logging utility function
 *
 * Note: the logging is done in an anonymous and untrackable way;
 *       user identity is represented as an id which changes every time the user opens the app
 *
 * @param msg The message to be logged
 * @param arg The additional arguments to be logged
 */
const log = function(msg, arg) {
  const timezoneOffset = (new Date()).getTimezoneOffset() * 60000; // offset in milliseconds
  const localISOTime = (new Date(Date.now() - timezoneOffset)).toISOString().replace(/[TZ]/g, ' ');
  const completeMessage = localISOTime + '    ' + msg;
  if (arg) {
    console.log(completeMessage, arg);
  } else {
    console.log(completeMessage);
  }
};

/**
 * Create an https server, and if requested, create an http server that redirects to the https server
 * @param app app created by `express()`
 * @param serverConfig server configurations
 * @returns {Server} The created https server
 */
const createServer = function(app, serverConfig) {
  if (serverConfig.isDebug === true) {
    return http.createServer(app).listen(serverConfig.httpPort, function () {
      log('(debug) http server listening on port %s', serverConfig.httpPort);
    });
  } else {
    // set up a https server
    const server = https.createServer({
      key: serverConfig.httpsCertificate.key,
      cert: serverConfig.httpsCertificate.cert,
      ca: serverConfig.httpsCertificate.ca,
    }, app);
    server.listen(serverConfig.httpsPort, function () {
      log('https server listening on port %s', serverConfig.httpsPort);
    });

    // set up a http server which redirect all requests to the https server
    if (serverConfig.isHttpServerOpen) {
      http.createServer(function (req, res) {
        res.writeHead(301, {'Location': 'https://' + req.headers['host'] + req.url});
        res.end();
      }).listen(serverConfig.httpPort, function () {
        log('http server listening on port %s', serverConfig.httpPort);
      });
    }
    return server;
  }
};

/**
 * Set up middlewares
 * @param app app created by `express()`
 */
const setUpMiddlewares = function(app) {
  // configure helmet
  app.use(helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      'script-src': ["'self'", 'cdn.bootcss.com'],
      'style-src': ["'self'", "'unsafe-inline'", 'cdn.bootcss.com'],
    },
  }));
  app.use(helmet.dnsPrefetchControl());
  app.use(helmet.expectCt());
  app.use(helmet.frameguard());
  app.use(helmet.hidePoweredBy());
  app.use(helmet.hsts());
  app.use(helmet.ieNoOpen());
  app.use(helmet.noSniff());
  app.use(helmet.permittedCrossDomainPolicies());
  app.use(helmet.referrerPolicy());
  app.use(helmet.xssFilter());

  // set up an access logger
  // create a write stream in append mode
  const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), {flags: 'a'});
  const logFormat = '[:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] :response-time ms';
  app.use(morgan(logFormat, {stream: accessLogStream}));

  // configure middlewares
  app.use(compression());
  app.use(express.static('public'));
  app.use(bodyParser.urlencoded({extended: false}));
  app.use(bodyParser.json());
  app.use(useragent.express());
};

/**
 * Set up request handlers
 * @param app app created by `express()`
 * @param transientStorage the server's in-memory storage
 */
const setUpRequestHandlers = function(app, transientStorage) {
  // serving apks
  app.get('/get-clumber', function (req, res) {
    if (req.useragent.isDesktop) {
      res.sendFile(__dirname + '/public/get-clumber.html');
    } else if (req.useragent.isAndroid || req.useragent.isAndroidTablet) {
      // send latest version
      fs.readFile(__dirname + '/versions/apk.json', function (err, data) {
        if (err) {
          res.status(500).end();
          throw err;
        }
        const versionName = JSON.parse(data).versions[0].name;
        const apkFileName = '/public/apk/clumber-' + versionName + '.apk';
        res.set({
          'Content-Disposition': 'attachment; filename="' + apkFileName + '"',
          'Content-Type': 'text/plain',
        });
        res.sendFile(__dirname + apkFileName);
      });
    } else {
      res.send('Sorry, Clumber does not support your device.');
    }
  });

  // statistics
  app.get('/stat', function (req, res) {
    res.json({
      numberOfOnlineUsers: transientStorage.enteredSockets.size
    });
  });

  // apis
  // check for updates
  app.get('/api/v2/check-update/apk/:versionCode', function (req, res) {
    const versionCode = parseInt(req.params.versionCode);
    // check parameter
    if (Number.isNaN(versionCode) || versionCode < 0) {
      res.status(400).send('versionCode not specified or invalid versionCode');
      return;
    }

    fs.readFile(__dirname + '/versions/apk.json', function (err, data) {
      if (err) {
        res.status(500).end();
        throw err;
      }

      const latestVersion = JSON.parse(data).versions[0];
      if (versionCode >= latestVersion.code) {
        res.json({
          'isLatest': true
        });
      } else {
        res.json({
          'isLatest': false,
          'latestVersion': latestVersion
        });
      }
    });
  });

  // get notices
  app.get('/api/v2/notice/:platform', function (req, res) {
    const platform = req.params.platform;
    // check parameter
    if (!platform) {
      res.status(400).send('platform not specified');
      return;
    }

    if (platform === 'android') {
      fs.readFile(__dirname + '/notices/android.json', function (err, data) {
        if (err) {
          res.status(500).end();
          throw err;
        }

        const noticeObj = JSON.parse(data);
        if (noticeObj.isPublished) {
          res.json({
            'hasNotice': true,
            'notice': noticeObj.notice
          });
        } else {
          res.json({
            'hasNotice': false
          });
        }
      });
    } else {
      res.status(400).send('invalid platform');
    }
  });
};

/**
 * Set up app with middlewares and request handlers
 * @param app app created by `express()`
 * @param transientStorage the server's in-memory storage
 */
const setUpApp = function(app, transientStorage) {
  setUpMiddlewares(app);
  setUpRequestHandlers(app, transientStorage);
};

/**
 * Set up SocketIO
 * @param server server created by `createServer()`
 * @param transientStorage the server's in-memory storage
 */
const setUpSocketIo = function(server, transientStorage) {
  // get socket io
  const io = SocketIOServer(server, {wsEngine: 'ws'});

  // socket tasks
  io.on('connection', function (socket) {
    log('+ on connection: ' + socket.id);

    const processFatalInvalidRequest = function (err) {
      log('fatal invalid request, error: ' + util.inspect(err));
      socket.emit('fatal invalid request', {error: err});
      socket.disconnect();
    };

    const processInvalidRequest = function (err) {
      log('invalid request, error: ' + util.inspect(err));
      socket.emit('invalid request', {error: err});
    };

    const validateCredential = function (credential) {
      if (!credential) {
        processFatalInvalidRequest('credential required');
        return false;
      } else if (!credential.code || !credential.name) {
        processFatalInvalidRequest('name and code required');
        return false;
      } else if (credential.name.length < 2 || !/^[0-9a-zA-Z\u4E00-\u9FA5\-_]*$/.test(credential.name)) {
        processFatalInvalidRequest('invalid name');
        return false;
      } else if (credential.code.length < 4 || !/^[0-9a-zA-Z]*$/.test(credential.code)) {
        processFatalInvalidRequest('invalid code');
        return false;
      }
      return true;
    };

    const processOnExitEvent = function () {
      if (!transientStorage.enteredSockets.has(socket.id)) {
        return;
      }
      const name = transientStorage.enteredSockets.get(socket.id);
      const code = transientStorage.users.get(name);

      // inform users in the same room
      socket.to(code).emit('user exited', {name: name});
      socket.leave(code);

      // destroy resources
      transientStorage.enteredSockets.delete(socket.id);
      transientStorage.users.delete(name);
      const room = transientStorage.rooms.get(code);
      room.userCount -= 1;
      room.names.delete(name);
      if (room.userCount <= 0) {
        transientStorage.rooms.delete(code);
      }
      log('user destructed: ' + socket.id);
    };

    // user enters the chatroom
    socket.on('entry', function (credential) {
      log('+ on entry: ' + socket.id);
      // validate credential
      if (!validateCredential(credential)) {
        return;
      }

      // check whether name is available
      if (transientStorage.users.has(credential.name)) {
        log('emitting "entry: name occupied"');
        socket.emit('entry: name occupied');
        return;
      }

      // create room
      const code = credential.code;
      if (!transientStorage.rooms.has(code)) {
        transientStorage.rooms.set(code, {userCount: 0, names: new Set()});
      }
      const room = transientStorage.rooms.get(code);
      if (room.userCount >= 2) {
        log('emitting "entry: code occupied"');
        socket.emit('entry: code occupied');
      } else {
        socket.join(code);
        room.userCount += 1;
        room.names.add(credential.name);
        transientStorage.users.set(credential.name, credential.code);
        transientStorage.enteredSockets.set(socket.id, credential.name);
        log('user constructed: ' + socket.id);
        if (room.userCount === 1) {
          log('emitting "entry: await"');
          socket.emit('entry: await');
        } else {
          log('emitting "entry: success"');
          const msg = 'entry: success';
          let chattingWithName = '';
          for (const name of room.names.keys()) {
            if (name !== credential.name) {
              chattingWithName = name;
              break;
            }
          }
          socket.emit(msg, {chattingWith: chattingWithName});
          socket.to(code).emit(msg, {chattingWith: credential.name});
        }
      }
    });

    // alice sends a key to bob
    socket.on('send key', function (key) {
      log('+ on send key: ' + socket.id);
      // check argument and state
      if (!key) {
        processFatalInvalidRequest('key required');
        return;
      }
      if (!key.publicKey) {
        processFatalInvalidRequest('key publicKey required');
        return;
      }
      if (!transientStorage.enteredSockets.has(socket.id)) {
        processInvalidRequest('not yet in a room');
        return;
      }

      // send message to clients
      const name = transientStorage.enteredSockets.get(socket.id);
      const code = transientStorage.users.get(name);

      socket.to(code).emit('receive key', {from: name, publicKey: key.publicKey});
    });

    // alice sends a message to bob
    socket.on('send message', function (message) {
      log('+ on send message: ' + socket.id);
      // check argument and state
      if (!message) {
        processFatalInvalidRequest('message required');
        return;
      }
      if (!message.text || !message.time) {
        processFatalInvalidRequest('message text and time required');
        return;
      }
      if (!transientStorage.enteredSockets.has(socket.id)) {
        processInvalidRequest('not yet in a room');
        return;
      }

      // send message to clients
      const name = transientStorage.enteredSockets.get(socket.id);
      const code = transientStorage.users.get(name);

      socket.to(code).emit('receive message', {from: name, text: message.text, time: message.time});
    });

    // user exits the chatroom
    socket.on('exit', function () {
      log('+ on exit: ' + socket.id);

      if (!transientStorage.enteredSockets.has(socket.id)) {
        // the user is not yet assigned a room
        // no need to proceed
        processInvalidRequest('not yet in a room');
        return;
      }

      processOnExitEvent();
    });

    // user disconnects
    socket.on('disconnect', function () {
      log('+ on disconnect: ' + socket.id);
      processOnExitEvent();
    });
  });
};

main();
