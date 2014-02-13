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
app.use(express.urlencoded());
app.use('/openid', skylith.express());

exports = module.exports = {
    get: get,
    post: post,
    endpoint: endpoint,
    checkAuth: checkAuth,
    openIdFields: openIdFields,
    dumpResponse: dumpResponse,
    identity: function(name) { return endpoint + '?u=' + encodeURIComponent(name); }
}

function get(path, params) {
    if (params) {
        var parsed = url.parse(path, true);
        for (var key in params) {
            parsed.query['openid.' + key] = params[key];
        }
        parsed.query['openid.ns'] = OPENID_NS;
        path = url.format(parsed);
    }
    return request(app).get(path).expect(standardExpectations);
}

function post(path, params) {
    var req = request(app).post(path);
    if (params) {
        req.type('form');
        for (var key in params) {
            req.send('openid.' + key + '=' + params[key]);
        }
        req.send('openid.ns=' + OPENID_NS);
    }
    return req.expect(standardExpectations);
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
        for (var key in expected) {
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
        if (!resQuery['openid.assoc_handle']) return errorMessage('openid.assoc_handle', resQuery, 'a value');
        if (!resQuery['openid.sig']) return errorMessage('openid.sig', resQuery, 'a value');

        if (!resQuery['openid.response_nonce']) return errorMessage('openid.response_nonce', resQuery, 'a value');
        var nonce = resQuery['openid.response_nonce'],
            nonceTime = Date.parse(nonce.substr(0, 20)),
            nonceTimezone = nonce.charAt(19),
            nonceAppendix = nonce.substr(20);

        if (Math.abs(Date.now() - nonceTime) > 2000) return 'Nonce time should be current server time';
        if (nonceTimezone !== 'Z') return errorMessage('Nonce timezone', nonceTimezone, 'Z');
        if (nonceAppendix.length < 1) return errorMessage('None appendix', 'empty', 'a value');

        if (!resQuery['openid.signed']) return errorMessage('openid.signed', resQuery, 'a value');
        var signed = resQuery['openid.signed'].split(',');
        if (signed.indexOf('op_endpoint') == -1) return 'Signed fields must include op_endpoint';
        if (signed.indexOf('return_to') == -1) return 'Signed fields must include return_to';
        if (signed.indexOf('response_nonce') == -1) return 'Signed fields must include response_nonce';
        if (signed.indexOf('assoc_handle') == -1) return 'Signed fields must include assoc_handle';
        if (resQuery['openid.claimed_id'] && signed.indexOf('claimed_id') == -1) return 'Signed fields must include claimed_id when claimed_id is present';
        if (resQuery['openid.identity'] && signed.indexOf('identity') == -1) return 'Signed fields must include identity when identity is present';
    },
    'cancel': function(req, res, reqQuery, resQuery) {}
}
