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
app.use(express.cookieParser('some big secret'));  // Required for signed cookies
app.use(skylith.express());

app.get('/', function(req, res, next) {
    skylith.sendDiscoveryResponse(req, res, next);
});

app.get('/login', function(req, res, next) {
    // Skylith will send a redirect to GET this route when it wants the user to login
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
        // Once you're happy with the authentication...
        skylith.completeAuth(req, res, req.body.username, next);
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
