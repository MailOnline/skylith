var express = require('express'),
    url = require('url'),
    Skylith = require('../skylith'),
    endpoint = 'http://localhost:3030/openid',  // This doesn't have to be real!
    skylith = new Skylith({ providerEndpoint: endpoint, checkAuth: checkAuthDelegate }),
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
    checkAuth: checkAuth,
    openIdFields: openIdFields,
    dumpResponse: dumpResponse
}

function checkAuthDelegate() {
    var args = Array.prototype.slice.call(arguments);
    currentCheckAuth.apply(null, args);
}

function checkAuth(options) {
    if (typeof currentCheckAuth !== 'undefined') throw new Error('checkAuth called twice without a callback');

    if (!('succeed' in options)) options.succeed = true;

    var error = "checkAuth wasn't called";

    currentCheckAuth = function(req, res, allowInteractive, context) {
        error = undefined;

        var authResponse = {
            context: context,
            identity: options.identity
        }

        if (allowInteractive !== options.ensureInteractive) {
            error = 'allowInteractive flag was ' + allowInteractive + '. Expected ' + !allowInteractive;
        }

        if (options.succeed) {
            skylith.completeAuth(req, res, authResponse);
        } else {
            skylith.rejectAuth(req, res, context);
        }
    }

    return function(res) {
        currentCheckAuth = undefined;

        if (error) return error;
    };
}

function openIdFields(expected) {
    expected['openid.ns'] = expected['openid.ns'] || 'http://specs.openid.net/auth/2.0';

    return function(res) {
        var fields = url.parse(res.get('location'), true).query;
        for (key in expected) {
            if (expected[key] !== fields[key]) return key + ' was ' + fields[key] + '. Expected ' + expected[key];
        }
    };
}

function dumpResponse(res) {
    console.log(url.parse(res.get('location'), true).query);
}

