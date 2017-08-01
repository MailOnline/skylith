// Copyright 2013-2014 Danny Yates

//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at

//        http://www.apache.org/licenses/LICENSE-2.0

//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const Skylith = require('../skylith');

// eslint-disable-next-line no-process-env
const PORT = process.env.PORT || 3000;
const ADDRESS = 'http://localhost:' + PORT + '/';
const PROVIDER_ENDPOINT = ADDRESS + 'openid';

const checkAuth = (req, res, allowInteraction, context) => {
  // Skylith wants to know if the user is already logged in or not. Check your session/cookies/whatever.
  // * If the user is already logged in, call skylith.completeAuth()
  // * If the user is NOT logged in and allowInteraction is true, store context somewhere (suggest not
  //   in a cookie because it can be quite big), prompt the user to login and when they're done call
  //   skylith.completeAuth()
  // * If the user is NOT logged in and allowInteraction is false, call skylith.rejectAuth()

  // This example assumes you're not already logged in
  if (allowInteraction) {
    req.session.skylith = context;
    res.redirect(302, '/login');
  }

  // TODO - else -> check_immediate isn't implemented yet
};

const skylith = new Skylith({
  checkAuth,
  providerEndpoint: PROVIDER_ENDPOINT
});

const app = express();

app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(express.session({
  cookie: {
    httpOnly: true,

    // We use sessions for maintaining state between Skylith calls so this can be quite short
    maxAge: 1 * 60 * 1000,
    signed: true
  },
  key: 's',

  // store: we're using the default memory store here. Don't use that in production! See http://www.senchalabs.org/connect/session.html#warning
  secret: 'some big secret for signed cookies'
}));
app.use('/openid', skylith.express());

app.get('/login', (req, res) => {
  // Inspect 'ax' in the stored context to see which attributes the RP is requesting.
  // You SHOULD prompt the user to release these attributes. The suggested flow here is
  // to authenticate the user (login), and then on a subsequent page request
  // permission to release data.
  res.type('text/html');
  res.end('<!DOCTYPE html><html><head><title>Login</title></head>' +
            '<body><h1>Who do you want to be today?</h1>' +
            '<form method="post">' +
            '<input type="text" name="username" value="Danny">' +
            '<button type="submit" name="login">Login</button>' +
            '<button type="submit" name="cancel">Cancel</button>' +
            '</form></body></html>');
});

app.post('/login', (req, res, next) => {
  if ('login' in req.body) {
    // Check the login credentials. If you're unhappy do whatever you would do. If you're
    // happy then do this...

    // Having got permission to release data, form an AX response (this should be done in
    // conjunction with the 'ax' attribute in the stored context to see what (if any)
    // attributes the Relying Party wants):
    const axResponse = {
      'http://axschema.org/contact/email': req.body.username.toLowerCase() + '@example.com',
      'http://axschema.org/namePerson': req.body.username + ' Smith',
      'http://axschema.org/namePerson/friendly': req.body.username
    };

    const authResponse = {
      ax: axResponse,
      context: req.session.skylith,
      identity: req.body.username
    };

    return skylith.completeAuth(req, res, authResponse);
  } else if ('cancel' in req.body) {
    // User cancelled authentication
    return skylith.rejectAuth(req, res, req.session.skylith);
  }

  return next();
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log('Running on ' + ADDRESS);
});
