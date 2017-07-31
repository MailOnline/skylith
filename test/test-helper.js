const {parse} = require('url');
const express = require('express');
const request = require('supertest');
const {assert} = require('chai');
const Skylith = require('../src/OpenIDProvider');

const OPENID_NS = 'http://specs.openid.net/auth/2.0';
const HEADER_DELEGATED = 'X-SkylithTests-Delegated';
const HEADER_DELEGATED_METHOD = 'X-SkylithTests-Method';

/* eslint-disable id-match */
const COMM_TYPE = {
  associate: 'direct',
  check_authentication: 'direct',
  checkid_immediate: 'indirect',
  checkid_setup: 'indirect'
};
/* eslint-enable id-match */
const endpoint = 'http://localhost:3030/openid';

let currentCheckAuth;

const checkAuthDelegate = (...args) => currentCheckAuth(...args);

const handleDelegated = (req, res, next) => {
  res.set(HEADER_DELEGATED, 'true');
  res.set(HEADER_DELEGATED_METHOD, req.method);
  next();
};

const skylith = new Skylith({
  checkAuth: checkAuthDelegate,
  providerEndpoint: endpoint
});
const app = express();

app.use(express.urlencoded());
app.use('/openid', skylith.express());
app.use(app.router);

app.all('/openid', handleDelegated);
app.all('/openid/*', handleDelegated);

const errorMessage = (what, actual, expected) => {
  const actualResult = typeof actual === 'object' ? actual[what] : actual;

  return what + ' was ' + actualResult + '. Expected ' + expected;
};

const expectationsByMode = {
  cancel: () => {},
  error: () => {},
  // eslint-disable-next-line id-match
  id_res: (req, res, reqParams, resParams) => {
    if (resParams['openid.op_endpoint'] !== endpoint) {
      return errorMessage('openid.op_endpoint', resParams, endpoint);
    }
    if (resParams['openid.return_to'] !== reqParams['openid.return_to']) {
      return errorMessage('openid.return_to', resParams, reqParams['openid.return_to']);
    }
    if (!resParams['openid.assoc_handle']) {
      return errorMessage('openid.assoc_handle', resParams, 'a value');
    }
    if (!resParams['openid.sig']) {
      return errorMessage('openid.sig', resParams, 'a value');
    }

    if (!resParams['openid.response_nonce']) {
      return errorMessage('openid.response_nonce', resParams, 'a value');
    }
    const nonce = resParams['openid.response_nonce'];
    const nonceTime = Date.parse(nonce.substr(0, 20));
    const nonceTimezone = nonce.charAt(19);
    const nonceAppendix = nonce.substr(20);

    if (Math.abs(Date.now() - nonceTime) > 2000) {
      return 'Nonce time should be current server time';
    }
    if (nonceTimezone !== 'Z') {
      return errorMessage('Nonce timezone', nonceTimezone, 'Z');
    }
    if (nonceAppendix.length < 1) {
      return errorMessage('None appendix', 'empty', 'a value');
    }

    if (!resParams['openid.signed']) {
      return errorMessage('openid.signed', resParams, 'a value');
    }
    const signed = resParams['openid.signed'].split(',');

    if (signed.indexOf('op_endpoint') === -1) {
      return 'Signed fields must include op_endpoint';
    }
    if (signed.indexOf('return_to') === -1) {
      return 'Signed fields must include return_to';
    }
    if (signed.indexOf('response_nonce') === -1) {
      return 'Signed fields must include response_nonce';
    }
    if (signed.indexOf('assoc_handle') === -1) {
      return 'Signed fields must include assoc_handle';
    }
    if (resParams['openid.claimed_id'] && signed.indexOf('claimed_id') === -1) {
      return 'Signed fields must include claimed_id when claimed_id is present';
    }
    if (resParams['openid.identity'] && signed.indexOf('identity') === -1) {
      return 'Signed fields must include identity when identity is present';
    }

    return null;
  },
  // eslint-disable-next-line id-match
  setup_needed: () => {}
};

const isDelegated = () => (res) => {
  assert.equal(res.get(HEADER_DELEGATED), 'true');
  assert.equal(res.get(HEADER_DELEGATED_METHOD), res.req.method);
};

const calculateCommType = (res, requestMode) => {
  let commType;

  commType = COMM_TYPE[requestMode];

  if (!commType) {
    // We can't tell the correct direct/indirect method using the openid.mode, so guess based on the HTTP method.
    if (res.req.method === 'GET') {
      // GETs are always indirect ("All direct requests are POSTs", ss 5.1.1)
      commType = 'indirect';
    } else if (res.req.method === 'POST') {
      // Assume direct; this matches the behaviour of the OSIS test suite
      commType = 'direct';
    }
  }

  return commType;
};

const parseIndirectResponseParams = (res) => parse(res.get('location'), true).query;

const parseDirectResponseParams = (res) => {
  const params = {};

  res.text.split('\n').forEach((line) => {
    if (line.length === 0) {
      return;
    }
    const match = line.match(/^([^:]+):(.+)$/);

    assert.isNotNull(match, 'Unable to parse key-value encoded response: ' + res.text);
    params['openid.' + match[1]] = match[2];
  });

  return params;
};

const standardExpectations = (reqParams) => (res) => {
  // Support discovery queries which aren't standard OpenID queries
  if (!reqParams['openid.ns']) {
    return null;
  }

  let resParams;

  const commType = calculateCommType(res, reqParams['openid.mode']);

  switch (commType) {
  case 'indirect': {
    resParams = parseIndirectResponseParams(res);
    if (res.status !== 302) {
      return errorMessage('HTTP result code', res.status, 302);
    }
    break;
  }
  case 'direct': {
    resParams = parseDirectResponseParams(res);
    if (res.status === 302) {
      return 'HTTP result code should not be 302 for direct responses';
    }
    break;
  }
  default: return 'Could not determing communication type (direct/indirect)';
  }

  let responseMode;

  responseMode = resParams['openid.mode'];

  // Attach the request and response params to the res object for later expectations to use
  res.reqParams = reqParams;
  res.resParams = resParams;

  if (resParams['openid.ns'] !== OPENID_NS) {
    return errorMessage('openid.ns', resParams, OPENID_NS);
  }

  if (commType === 'indirect') {
    if (!responseMode) {
      return errorMessage('openid.mode', resParams, 'a value');
    }
  } else if (res.status === 400) {
    // Direct error responses (400's) don't explicitly include the 'openid.mode' parameter
    responseMode = 'error';
  }

  const expectations = expectationsByMode[responseMode];

  assert.isFunction(expectations, 'Response mode ' + responseMode + ' has no expectations defined');

  return expectations(res.req, res, reqParams, resParams);
};

const get = (path, params) => {
  const req = request(app).get(path);
  const args = {};

  if (params) {
    for (const key of Object.keys(params)) {
      args['openid.' + key] = params[key];
    }
    args['openid.ns'] = OPENID_NS;
    req.query(args);
  }

  return req.expect(standardExpectations(args));
};

const post = (path, params) => {
  const req = request(app).post(path);
  const args = {};

  if (params) {
    req.type('form');
    for (const key of Object.keys(params)) {
      args['openid.' + key] = params[key];
    }
    args['openid.ns'] = OPENID_NS;
    req.send(args);
  }

  return req.expect(standardExpectations(args));
};

const checkAuth = (options) => {
  if (currentCheckAuth) {
    throw new TypeError('checkAuth called twice without a callback');
  }

  if (!('succeed' in options)) {
    options.succeed = true;
  }

  let err;

  err = 'checkAuth wasn\'t called';

  currentCheckAuth = (req, res, allowInteractive, context) => {
    err = undefined;

    const authResponse = {
      context,
      identity: options.identity
    };

    if (allowInteractive !== options.ensureInteractive) {
      err = errorMessage('allowInteractive', allowInteractive, !allowInteractive);
    }

    if (options.succeed) {
      skylith.completeAuth(req, res, authResponse);
    } else {
      skylith.rejectAuth(req, res, context);
    }
  };

  return () => {
    currentCheckAuth = undefined;

    return err;
  };
};

const error = (message) => (res) => {
  const commType = calculateCommType(res, res.reqParams['openid.mode']);

  const checkDirectError = () => {
    assert.equal(res.status, 400);
    assert.equal(res.resParams['openid.error'], message);
  };

  const checkIndirectError = () => {
    assert.equal(res.status, 302);
    assert.equal(res.resParams['openid.mode'], 'error');
    assert.equal(res.resParams['openid.error'], message);
  };

  switch (commType) {
  case 'indirect': return checkIndirectError();
  case 'direct': return checkDirectError();
  default: return 'Could not determing communication type (direct/indirect)';
  }
};

const openIdFields = (expected) => (res) => {
  const resParams = res.resParams;

  for (const key of Object.keys(expected)) {
    if (expected[key] !== resParams['openid.' + key]) {
      return errorMessage('openid.' + key, resParams, expected[key]);
    }
  }

  return null;
};

const identity = (name) => endpoint + '?u=' + encodeURIComponent(name);

module.exports = {
  checkAuth,
  endpoint,
  error,
  get,
  identity,
  isDelegated,
  openIdFields,
  post
};
