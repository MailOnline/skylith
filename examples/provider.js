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

var PORT = process.env.PORT || 3000,
    ADDRESS = 'http://localhost:' + PORT + '/',
    PROVIDER_ENDPOINT = ADDRESS + 'openid';

var express = require('express'),
    Skylith = require('../skylith'),
    skylith = new Skylith({
        providerEndpoint: PROVIDER_ENDPOINT,
        checkAuth: checkAuth
    });

var app = express();

app.use(express.urlencoded());
app.use(express.cookieParser());
app.use(express.session({
    key: 's',
    // store: we're using the default memory store here. Don't use that in production! See http://www.senchalabs.org/connect/session.html#warning
    secret: 'some big secret for signed cookies',
    cookie: {
        signed: true,
        httpOnly: true,
        maxAge: 1 * 60 * 1000   // We use sessions for maintaining state between Skylith calls so this can be quite short
    }
}));
app.use('/openid', skylith.express());

app.get('/login', function(req, res, next) {
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

app.post('/login', function(req, res, next) {
    if ('login' in req.body) {
        // Check the login credentials. If you're unhappy do whatever you would do. If you're
        // happy then do this...

        // Having got permission to release data, form an AX response (this should be done in
        // conjunction with the 'ax' attribute in the stored context to see what (if any)
        // attributes the Relying Party wants):
        var axResponse = {
            'http://axschema.org/namePerson/friendly': req.body.username,
            'http://axschema.org/contact/email': req.body.username.toLowerCase() + '@example.com',
            'http://axschema.org/namePerson': req.body.username + ' Smith'
        }

        var authResponse = {
            context: req.session.skylith,
            identity: req.body.username,
            ax: axResponse
        }

        skylith.completeAuth(req, res, authResponse, next);
    } else if ('cancel' in req.body) {
        // User cancelled authentication
        skylith.rejectAuth(req, res, req.session.skylith, next);
    } else {
        next();
    }
});

app.listen(PORT, function() {
    console.log('Running on ' + ADDRESS);
});


function checkAuth(req, res, allowInteraction, context) {
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
    } else {
        // TODO - check_immediate isn't implemented yet
    }
}
