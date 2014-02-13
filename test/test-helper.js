var express = require('express'),
    url = require('url'),
    request = require('supertest'),
    Skylith = require('../skylith'),
    endpoint = 'http://localhost:3030/openid',  // This doesn't have to be real!
    skylith = new Skylith({ providerEndpoint: endpoint, checkAuth: checkAuthDelegate }),
    app = express();

var OPENID_NS = 'http://specs.openid.net/auth/2.0';

var currentCheckAuth;

// app.use('/', function(req, res, next) {
//     console.log(req.method, req.url);
//     next();
// });

app.use('/openid', skylith.express());

exports = module.exports = {
    get: get,
    endpoint: endpoint,
    checkAuth: checkAuth,
    openIdFields: openIdFields,
    dumpResponse: dumpResponse
}

function get(path, params) {
    if (params) {
        var parsed = url.parse(path, true);
        for (key in params) {
            parsed.query['openid.' + key] = params[key];
        }
       path = url.format(parsed);
    }
    return request(app).get(path).expect(standardExpectations);
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
            error = errorMessage('allowInteractive', allowInteractive, !allowInteractive);
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
    return function(res) {
        var fields = responseQuery(res);
        for (key in expected) {
            if (expected[key] !== fields['openid.' + key]) return errorMessage('openid.' + key, fields, expected[key]);
        }
    };
}

function dumpResponse(res) {
    console.log(responseQuery(res));
}

function errorMessage(what, actual, expected) {
    if (typeof actual === 'object') {
        actual = actual[what];
    }

    return what + ' was ' + actual + '. Expected ' + expected;
}

function responseQuery(res) {
    return url.parse(res.get('location'), true).query;
}

function standardExpectations(res) {
    var reqQuery = url.parse(res.req.path, true).query;

    // Support discovery queries which aren't standard OpenID queries
    if (!reqQuery['openid.ns']) return;

    var resQuery = responseQuery(res);

    if (resQuery['openid.ns'] !== OPENID_NS) return errorMessage('openid.ns', resQuery, OPENID_NS);
    if (!resQuery['openid.mode']) return errorMessage('openid.mode', resQuery, 'a value');

    return expectationsByMode[resQuery['openid.mode']](res.req, res, reqQuery, resQuery);
}

var expectationsByMode = {
    'id_res': function(req, res, reqQuery, resQuery) {
        if (resQuery['openid.op_endpoint'] !== endpoint) return errorMessage('openid.op_endpoint', resQuery, endpoint);
        if (resQuery['openid.return_to'] !== reqQuery['openid.return_to']) return errorMessage('openid.return_to', resQuery, reqQuery['openid.return_to']);
    }
}
