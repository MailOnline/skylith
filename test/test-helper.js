var express = require('express'),
    Skylith = require('../skylith'),
    endpoint = 'http://localhost:3030/openid',  // This doesn't have to be real!
    skylith = new Skylith({ providerEndpoint: endpoint, checkAuth: checkAuth }),
    app = express();

var currentCheckAuth;

// app.use('/', function(req, res, next) {
//     console.log(req.method, req.url);
//     next();
// });

app.use('/openid', skylith.express());

exports = module.exports = {
    endpoint: endpoint,
    app: app,
    expectCheckAuth: expectCheckAuth
}

function checkAuth() {
    var args = Array.prototype.slice.call(arguments);
    currentCheckAuth.apply(null, args);
}

function expectCheckAuth(options) {
    if (typeof currentCheckAuth !== 'undefined') throw new Error('expectCheckAuth called twice without a callback');

    var wasCalled = false;

    currentCheckAuth = function(req, res, allowInteractive, context) {
        var authResponse = {
            context: context,
            identity: options.identity
        }

        wasCalled = true;

        if (options.succeed) {
            skylith.completeAuth(req, res, authResponse);
        }
    }

    return function(res) {
        currentCheckAuth = undefined;

        if (!wasCalled) return 'checkAuth wasn\'t called';
    };
}
