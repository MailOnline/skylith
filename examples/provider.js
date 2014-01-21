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

var express = require('express'),
    Skylith = require('../skylith'),
    skylith = new Skylith();

var PORT = process.env.PORT || 3000;

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
        maxAge: 1 * 60 * 1000   // Skylith uses sessions for maintaining state between calls so this can be quite short
    }
}));
app.use(skylith.express());

app.get('/', function(req, res, next) {
    skylith.sendDiscoveryResponse(req, res, next);
});

app.get('/login', function(req, res, next) {
    // Skylith will send a redirect to GET this route when it wants the user to login.
    // Inspect req.session.openid.ax to see which attributes the RP is requesting. You
    // SHOULD prompt the user to release these attributes. The suggest flow here is to
    // authenticate the user (login), and then on a subsequent page request permission
    // to release data.
    res.type('text/html');
    res.end('<!DOCTYPE html><html><head><title>Login</title></head>' +
            '<body><h1>Who do you want to be today?</h1>' +
            '<form method="post">' +
            '<input type="text" name="username" value="Danny">' +
            '<button type="submit" name="login">Login</button>' +
            '<button type="submit" name="cancel">Cancel</button>' +
            '</form></body></html>');
});

app.get('/users/:user', function(req, res, next) {
    // Check if the user is a valid username, and if so...
    skylith.sendDiscoveryResponse(req, res, req.params.user, next);
});

app.post('/login', function(req, res, next) {
    if ('login' in req.body) {
        // Having got permission to release data, form an AX response:
        var axResponse = {
            'http://axschema.org/namePerson/friendly': req.body.username,
            'http://axschema.org/contact/email': req.body.username.toLowerCase() + '@example.com',
            'http://axschema.org/namePerson': req.body.username + ' Smith'
        }

        var authResponse = {
            identity: 'http://localhost:3000/users/' + req.body.username.toLowerCase(),
            ax: axResponse
        }

        // Once you're happy with the authentication...
        skylith.completeAuth(req, res, authResponse, next);
    } else if ('cancel' in req.body) {
        // User cancelled authentication
        skylith.cancelAuth(req, res, next);
    } else {
        next();
    }
});

app.listen(PORT, function() {
    console.log('Running on http://localhost:' + PORT);
});
