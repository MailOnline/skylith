var express = require('express'),
    url = require('url'),
    request = require('supertest'),
    chai = require('chai'),
    assert = chai.assert,
    Skylith = require('../skylith'),
    endpoint = 'http://localhost:3030/openid',  // This doesn't have to be real!
    skylith = new Skylith({ providerEndpoint: endpoint, checkAuth: checkAuthDelegate }),
    app = express();

var OPENID_NS = 'http://specs.openid.net/auth/2.0'
    HEADER_DELEGATED = 'X-SkylithTests-Delegated',
    HEADER_DELEGATED_METHOD = 'X-SkylithTests-Method';

var COMM_TYPE = {
    'checkid_setup': 'indirect',
    'checkid_immediate': 'indirect',
    'associate': 'direct',
    'check_authentication': 'direct'
}

var currentCheckAuth;

// app.use('/', function(req, res, next) {
//     console.log(req.method, req.url);
//     next();
// });

app.use(express.urlencoded());
app.use('/openid', skylith.express());
app.use(app.router);

app.all('/openid', handleDelegated);
app.all('/openid/*', handleDelegated);

exports = module.exports = {
    get: get,
    post: post,
    error: error,
    endpoint: endpoint,
    checkAuth: checkAuth,
    openIdFields: openIdFields,
    isDelegated: isDelegated,
    identity: function(name) { return endpoint + '?u=' + encodeURIComponent(name); }
}

function handleDelegated(req, res, next) {
    res.set(HEADER_DELEGATED, 'true');
    res.set(HEADER_DELEGATED_METHOD, req.method);
    next();
}

function isDelegated() {
    return function(res) {
        assert.equal(res.get(HEADER_DELEGATED), 'true');
        assert.equal(res.get(HEADER_DELEGATED_METHOD), res.req.method);
    }
}

function get(path, params) {
    var req = request(app).get(path),
        args = {};

    if (params) {
        // req.type('form');
        for (var key in params) {
            args['openid.' + key] = params[key];
        }
        args['openid.ns'] = OPENID_NS;
        req.query(args);
    }
    return req.expect(standardExpectations(args));
}

function post(path, params) {
    var req = request(app).post(path),
        args = {};

    if (params) {
        req.type('form');
        for (var key in params) {
            args['openid.' + key] = params[key];
        }
        args['openid.ns'] = OPENID_NS;
        req.send(args);
    }
    return req.expect(standardExpectations(args));
}

function calculateCommType(res, requestMode) {
    var commType = COMM_TYPE[requestMode];

    if (!commType) {
        // We can't tell the correct direct/indirect method using the openid.mode, so guess based on the HTTP method.
        if (res.req.method == 'GET') {
            // GETs are always indirect ("All direct requests are POSTs", ss 5.1.1)
            commType = 'indirect';
        } else if (res.req.method == 'POST') {
            // Assume direct; this matches the behaviour of the OSIS test suite
            commType = 'direct';
        }
    }

    return commType;
}

function error(message) {
    return function(res) {
        var commType = calculateCommType(res, res.reqParams['openid.mode']);

        if (commType == 'indirect') {
            checkIndirectError();
        } else if (commType == 'direct') {
            checkDirectError();
        } else {
            return 'Could not determing communication type (direct/indirect)'
        }

        function checkDirectError() {
            assert.equal(res.status, 400);
            assert.equal(res.resParams['openid.error'], message);
        }

        function checkIndirectError() {
            assert.equal(res.status, 302);
            assert.equal(res.resParams['openid.mode'], 'error');
            assert.equal(res.resParams['openid.error'], message);
        }
    }
}

function checkAuthDelegate() {
    currentCheckAuth.apply(null, arguments);
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
    }
}

function openIdFields(expected) {
    return function(res) {
        var resParams = res.resParams;
        for (var key in expected) {
            if (expected[key] !== resParams['openid.' + key]) return errorMessage('openid.' + key, resParams, expected[key]);
        }
    }
}

function errorMessage(what, actual, expected) {
    if (typeof actual === 'object') {
        actual = actual[what];
    }

    return what + ' was ' + actual + '. Expected ' + expected;
}

function parseDirectResponseParams(res) {
    var params = {};
    res.text.split('\n').forEach(function(line) {
        if (line.length === 0) return;
        var match = line.match(/^([^:]+):(.+)$/);
        assert.isNotNull(match, 'Unable to parse key-value encoded response: ' + res.text);
        params['openid.' + match[1]] = match[2];
    });
    return params;
}

function parseIndirectResponseParams(res) {
    return url.parse(res.get('location'), true).query;
}

function standardExpectations(reqParams) {
    return function(res) {
        // Support discovery queries which aren't standard OpenID queries
        if (!reqParams['openid.ns']) return;

        var commType = calculateCommType(res, reqParams['openid.mode']),
            resParams;

        if (commType == 'indirect') {
            resParams = parseIndirectResponseParams(res);
            if (res.status !== 302) return errorMessage('HTTP result code', res.status, 302);
        } else if (commType == 'direct') {
            resParams = parseDirectResponseParams(res);
            if (res.status === 302) return 'HTTP result code should not be 302 for direct responses';
        } else {
            return 'Could not determing communication type (direct/indirect)'
        }

        var responseMode = resParams['openid.mode'];

        // Attach the request and response params to the res object for later expectations to use
        res.reqParams = reqParams;
        res.resParams = resParams;

        if (resParams['openid.ns'] !== OPENID_NS) return errorMessage('openid.ns', resParams, OPENID_NS);

        if (commType == 'indirect') {
            if (!responseMode) return errorMessage('openid.mode', resParams, 'a value');
        } else {
            // Direct error responses (400's) don't explicitly include the 'openid.mode' parameter
            if (res.status == 400) responseMode = 'error';
        }

        var expectations = expectationsByMode[responseMode];
        assert.isFunction(expectations, 'Response mode ' + responseMode + ' has no expectations defined');
        return expectations(res.req, res, reqParams, resParams);
    }
}

var expectationsByMode = {
    'id_res': function(req, res, reqParams, resParams) {
        if (resParams['openid.op_endpoint'] !== endpoint) return errorMessage('openid.op_endpoint', resParams, endpoint);
        if (resParams['openid.return_to'] !== reqParams['openid.return_to']) return errorMessage('openid.return_to', resParams, reqParams['openid.return_to']);
        if (!resParams['openid.assoc_handle']) return errorMessage('openid.assoc_handle', resParams, 'a value');
        if (!resParams['openid.sig']) return errorMessage('openid.sig', resParams, 'a value');

        if (!resParams['openid.response_nonce']) return errorMessage('openid.response_nonce', resParams, 'a value');
        var nonce = resParams['openid.response_nonce'],
            nonceTime = Date.parse(nonce.substr(0, 20)),
            nonceTimezone = nonce.charAt(19),
            nonceAppendix = nonce.substr(20);

        if (Math.abs(Date.now() - nonceTime) > 2000) return 'Nonce time should be current server time';
        if (nonceTimezone !== 'Z') return errorMessage('Nonce timezone', nonceTimezone, 'Z');
        if (nonceAppendix.length < 1) return errorMessage('None appendix', 'empty', 'a value');

        if (!resParams['openid.signed']) return errorMessage('openid.signed', resParams, 'a value');
        var signed = resParams['openid.signed'].split(',');
        if (signed.indexOf('op_endpoint') == -1) return 'Signed fields must include op_endpoint';
        if (signed.indexOf('return_to') == -1) return 'Signed fields must include return_to';
        if (signed.indexOf('response_nonce') == -1) return 'Signed fields must include response_nonce';
        if (signed.indexOf('assoc_handle') == -1) return 'Signed fields must include assoc_handle';
        if (resParams['openid.claimed_id'] && signed.indexOf('claimed_id') == -1) return 'Signed fields must include claimed_id when claimed_id is present';
        if (resParams['openid.identity'] && signed.indexOf('identity') == -1) return 'Signed fields must include identity when identity is present';
    },
    'cancel': function(req, res, reqParams, resParams) {},
    'setup_needed': function(req, res, reqParams, resParams) {},
    'error': function(req, res, reqParams, resParams) {}
}
