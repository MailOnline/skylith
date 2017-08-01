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

const crypto = require('crypto');
const url = require('url');
const {format, isArray, promisify} = require('util');
const {isWebUri} = require('valid-url');
const {normalize, parse, serialize} = require('uri-js');
const messageFactory = require('./helpers/messageFactory');
const Association = require('./helpers/Association');
const MemoryAssociationStore = require('./helpers/MemoryAssociationStore');
const MemoryNonceStore = require('./helpers/MemoryNonceStore');

const DH_MODULUS_HEX = 'DCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E' +
                     'F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557' +
                     '7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382' +
                     '6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB';
const DH_MODULUS_ENCODED = Buffer.from(DH_MODULUS_HEX, 'hex').toString('base64');

// TODO duplicated
const OPENID_NS = 'http://specs.openid.net/auth/2.0';
const OPENID_AX_NS = 'http://openid.net/srv/ax/1.0';
const HTML_DISCOVERY_RESPONSE_TEMPLATE = `<!DOCTYPE html>
<html>
<head>
<title>OpenID Provider</title>
<link rel="openid2.provider" href="%s">
</head>
<body>
</body>
</html>
`;
const HTML_VALIDATION_RESPONSE_TEMPLATE = `<!DOCTYPE html>
<html>
<head>
<title>OpenID Provider</title>
<link rel="openid2.provider" href="%s">
<link rel="openid2.local_id" href="%s">
</head>
<body>
</body>
</html>
`;
const XRDS_DISCOVERY_RESPONSE_TEMPLATE = `<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
<XRD>
<Service priority="0">
<Type>http://specs.openid.net/auth/2.0/%s</Type>
<Type>http://openid.net/srv/ax/1.0</Type>
<URI>%s</URI>
</Service>
</XRD>
</xrds:XRDS>
`;

const randomBytesAsync = promisify(crypto.randomBytes);

class OpenIDProvider {
  constructor (options) {
    this.associationStore = options.associationStore || new MemoryAssociationStore();
    this.nonceStore = options.nonceStore || new MemoryNonceStore();
    this.providerEndpoint = options.providerEndpoint;
    this.checkAuth = options.checkAuth;
    this.associationExpirySecs = options.associationExpirySecs || 30;
    this.nonceExpirySecs = options.nonceExpirySecs || 30;
  }

  express () {
    return this.middleware.bind(this);
  }

  completeAuth (req, res, authResponse) {
    this.checkIdComplete(req, res, authResponse);
  }

  rejectAuth (req, res, context) {
    this.checkIdCancel(req, res, context);
  }

  middleware (req, res, next) {
    switch (req.method) {
    case 'POST': return this.handlePost(req, res, next);
    case 'GET': return this.handleGet(req, res, next);
    default: return next();
    }
  }

  handlePost (req, res, next) {
    const request = messageFactory.fromBody(req);

    // not OpenID (4.1.2)
    if (request.ns !== OPENID_NS) {
      return next();
    }

    // 8.1
    if (request.mode === 'associate') {
      return this.associate(request, req, res, next);
    }

    // 11.4.2.1
    if (request.mode === 'check_authentication') {
      return this.checkAuthentication(request, req, res, next);
    }

    // checkid_setup can be posted
    if (request.mode === 'checkid_setup') {
      return this.checkIdSetup(request, req, res);
    }

    // checkid_immediate can be posted
    if (request.mode === 'checkid_immediate') {
      return this.checkIdImmediate(request, req, res);
    }

    // unknown direct request
    return this.constructor.sendDirectResponseError(res, {
      error: 'Unknown or unsupported direct request'
    });
  }

  handleGet (req, res, next) {
    const request = messageFactory.fromQueryArgs(req);

    // not OpenID (4.1.2)
    if (request.ns !== OPENID_NS) {
      // relative to where the middleware is mounted
      if (url.parse(req.url).pathname === '/') {
        // Discovery
        if (Object.keys(req.query).length === 1 && req.query.u) {
          return this.sendDiscoveryResponse(req, res, req.query.u);
        } else {
          return this.sendDiscoveryResponse(req, res);
        }
      }

      return next();
    }

    if (request.mode === 'checkid_setup') {
      return this.checkIdSetup(request, req, res);
    }

    if (request.mode === 'checkid_immediate') {
      return this.checkIdImmediate(request, req, res);
    }

    // unknown indirect request
    return this.constructor.sendIndirectResponseError(request, res, 'Unknown or unsupported indirect request');
  }

  identityToUrl (identity) {
    return this.providerEndpoint + '?u=' + encodeURIComponent(identity);
  }

  sendDiscoveryResponse (req, res, identity) {
    if (req.accepts('application/xrds+xml')) {
      res.type('application/xrds+xml');

      if (identity) {
        return res.end(format(XRDS_DISCOVERY_RESPONSE_TEMPLATE, 'signon', this.providerEndpoint));
      }

      return res.end(format(XRDS_DISCOVERY_RESPONSE_TEMPLATE, 'server', this.providerEndpoint));
    } else if (req.accepts('text/html')) {
      res.type('text/html');

      if (identity) {
        return res.end(format(HTML_VALIDATION_RESPONSE_TEMPLATE, this.providerEndpoint, this.identityToUrl(identity)));
      }

      return res.end(format(HTML_DISCOVERY_RESPONSE_TEMPLATE, this.providerEndpoint));
    }

    // "Not acceptable"
    return res.sendStatus(406);
  }

  associate (request, req, res, next) {
    if (request.session_type === 'no-encryption') {
      if (req.secure) {
        return this.unencryptedAssociation(request, res, next);
      }

      // 8.1.1, 8.4.1
      this.unsupportedAssociation(res, 'Cannot create a "no-encryption" session without using HTTPS');
    } else if (request.session_type === 'DH-SHA1') {
      return this.diffieHellmanAssociate(request, res, 'sha1', next);
    } else if (request.session_type === 'DH-SHA256') {
      return this.diffieHellmanAssociate(request, res, 'sha256', next);
    }

    return this.unsupportedAssociation(res, 'Session type not recognised: ' + request.session_type);
  }

  unsupportedAssociation (res, message) {
    // 8.2.4
    /* eslint-disable id-match */
    this.constructor.sendDirectResponseError(res, {
      assoc_type: 'HMAC-SHA256',
      error: message,
      error_code: 'unsupported-type',
      session_type: 'DH-SHA256'
    });
    /* eslint-enable id-match */
  }

  checkIdSetup (request, req, res) {
    this.checkId(request, req, res, true);
  }

  checkIdImmediate (request, req, res) {
    this.checkId(request, req, res, false);
  }

  checkId (request, req, res, interactive) {
    if (!request.return_to && !request.realm) {
      // 9.1
      return this.constructor.sendIndirectResponseError(request, res, 'checkid_setup/checkid_immediate must specify one (or both) of return_to and realm');
    }

    if (request.realm) {
      let wildcardRealm;
      let parsedRealm;

      // Validate realm. 9.2
      // Use a third-party parser instead of the node URL module to get wildcard support
      parsedRealm = parse(request.realm);
      wildcardRealm = false;

      if (parsedRealm.errors.length > 0) {
        return this.constructor.sendIndirectResponseError(request, res, 'Invalid realm');
      }

      if (parsedRealm.fragment) {
        return this.constructor.sendIndirectResponseError(request, res, 'Realm cannot contain a fragment');
      }

      if (parsedRealm.host.slice(0, 2) === '*.') {
        // replace the wildcard realm with a non-wildcard
        parsedRealm.host = parsedRealm.host.slice(2);
        wildcardRealm = true;
      }

      parsedRealm = normalize(parsedRealm);

      // Now revalidate with something that specifically understands HTTP and HTTPS URLs (instead of general URIs)
      if (!isWebUri(serialize(parsedRealm))) {
        return this.constructor.sendIndirectResponseError(request, res, 'Invalid realm');
      }

      if (request.return_to) {
        const parsedReturnTo = normalize(parse(request.return_to));

        // The schemes and ports must be equal
        if (parsedRealm.scheme !== parsedReturnTo.scheme || parsedRealm.port !== parsedReturnTo.port) {
          return this.constructor.sendIndirectResponseError(request, res, 'The return_to URL does not match the realm');
        }

        // The pathnames must be equal or else the return_to pathname must be a "sub-directory" of the realm pathname. 9.2
        if (!(parsedRealm.pathname === parsedReturnTo.pathname || parsedReturnTo.pathname.indexOf(parsedRealm.pathname + '/') === 0)) {
          return this.constructor.sendIndirectResponseError(request, res, 'The return_to URL does not match the realm');
        }

        // Hostnames match or the return_to hostname must END with '.'+realm hostname IFF realm was wildcarded
        if (!(parsedRealm.hostname === parsedReturnTo.hostname ||
          wildcardRealm && parsedReturnTo.hostname.substr(parsedReturnTo.hostname.length - parsedRealm.hostname.length - 1) === '.' + parsedRealm.hostname)) {
          return this.constructor.sendIndirectResponseError(request, res, 'The return_to URL does not match the realm');
        }
      }
    }

    const context = {
      interactive,
      request
    };
    const axRequest = messageFactory.getExtension(request, OPENID_AX_NS);

    if (axRequest) {
      if (axRequest.fields.mode !== 'fetch_request') {
        return this.constructor.sendIndirectResponseError(request, res, 'Unexpected attribute exchange mode');
      }

      context.ax = axRequest;
    }

    return this.checkAuth(req, res, interactive, context);
  }

  checkIdCancel (req, res, context) {
    const request = context.request;

    if (!request) {
      return res.send(400);
    }

    return this.constructor.sendIndirectResponse(request, res, {
      mode: context.interactive ? 'cancel' : 'setup_needed'
    });
  }

  checkIdComplete (req, res, authResponse) {
    const context = authResponse.context;
    const request = context.request;
    const nonce = {
      expiry: Date.now() + this.nonceExpirySecs * 1000,
      id: new Date().toISOString().slice(0, -5) + 'Z' + crypto.randomBytes(4).toString('hex')
    };
    let association;

    if (!request) {
      return res.send(400);
    }

    /* eslint-disable id-match */
    const response = {
      claimed_id: this.identityToUrl(authResponse.identity),
      identity: this.identityToUrl(authResponse.identity),
      mode: 'id_res',
      op_endpoint: this.providerEndpoint,
      response_nonce: nonce.id,
      return_to: request.return_to
    };
    /* eslint-enable id-match */

    if (context.ax) {
      const axResponse = authResponse.ax;
      const nsAlias = context.ax.alias;

      // Preserve the namespace alias from the request. Nothing in the spec mandates this,
      // but there are several broken RPs which expect it - notably some combination
      // of Spring Security and OpenID4Java
      response['ns.' + nsAlias] = OPENID_AX_NS;
      response[nsAlias + '.mode'] = 'fetch_response';

      for (const type of Object.keys(axResponse)) {
        const value = axResponse[type];
        let alias;

        // Preserve the type alias from the request. Nothing in the spec mandates this,
        // but there are several broken RPs which expect it - notably some combination
        // of Spring Security and OpenID4Java
        for (const attr in context.ax.fields) {
          if (attr.slice(0, 5) === 'type.' && context.ax.fields[attr] === type) {
            alias = attr.substr(5);
            break;
          }
        }

        if (alias) {
          response[nsAlias + '.type.' + alias] = type;

          if (isArray(value)) {
            response[nsAlias + '.count.' + alias] = value.length;
            for (let index = 0; index < value.length; index++) {
              response[nsAlias + '.value.' + alias + '.' + (index + 1)] = value[index];
            }
          } else {
            response[nsAlias + '.value.' + alias] = value;
          }
        }
      }
    }

    const sendResponse = async () => {
      try {
        await this.nonceStore.put(nonce);

        return this.constructor.sendIndirectResponse(request, res, response);
      } catch (error) {
        return this.constructor.internalError(error, res);
      }
    };

    const signResponse = () => {
      const hmac = crypto.createHmac(association.algorithm, Buffer.from(association.secret, 'base64'));
      const message = messageFactory.toForm(response);

      hmac.update(message.body);

      response.sig = hmac.digest('base64');
      response.signed = message.fields.join(',');

      sendResponse();
    };

    const privateAssociation = async () => {
      if (association) {
        // eslint-disable-next-line id-match
        response.assoc_handle = association.handle;

        return signResponse();
      } else {
        try {
          // Make a "private association". The spec is vague here. For example, how do we know the client supports the algorithm we choose?
          const {hashAlgorithm, macBuffer} = await this.constructor.createMac('HMAC-SHA256');

          association = new Association(hashAlgorithm, macBuffer.toString('base64'), this.associationExpirySecs, true);
          await this.associationStore.put(association);
          // eslint-disable-next-line id-match
          response.assoc_handle = association.handle;

          return signResponse();
        } catch (error) {
          return this.constructor.internalError(error, res);
        }
      }
    };

    const checkAssociation = async () => {
      if (request.assoc_handle) {
        try {
          association = await this.associationStore.get(request.assoc_handle);

          let remove;

          remove = false;

          if (association && association.expiry < Date.now()) {
            // Association expired
            // Proceed as if no handle specified. s10
            remove = true;
            association = undefined;
          }

          if (!association) {
            // Not found or expired
            // eslint-disable-next-line id-match
            response.invalidate_handle = request.assoc_handle;
          }

          if (remove) {
            try {
              await this.associationStore.delete(request.assoc_handle);

              return this.privateAssociation();
            } catch (error) {
              return this.constructor.internalError(error, res);
            }
          }

          return privateAssociation();
        } catch (error) {
          return this.constructor.internalError(error, res);
        }
      } else {
        return privateAssociation();
      }
    };

    return checkAssociation();
  }

  async unencryptedAssociation (request, res, next) {
    try {
      const {hashAlgorithm, macBuffer} = await this.constructor.createMac(request.assoc_type);

      if (!macBuffer) {
        return this.unsupportedAssociation(res, 'Association type not recognised: ' + request.assoc_type);
      }

      const association = new Association(hashAlgorithm, macBuffer.toString('base64'), this.associationExpirySecs, false);

      try {
        await this.associationStore.put(association);

        /* eslint-disable id-match */
        const response = {
          assoc_handle: association.handle,
          assoc_type: request.assoc_type,
          expires_in: this.associationExpirySecs,
          mac_key: macBuffer.toString('base64'),
          session_type: request.session_type
        };
        /* eslint-enable id-match */

        return this.constructor.sendDirectResponse(res, response);
      } catch (error) {
        return this.constructor.internalError(error, res, next);
      }
    } catch (error) {
      return this.constructor.internalError(error, res, next);
    }
  }

  async diffieHellmanAssociate (request, res, dhHash, next) {
    try {
      const {hashAlgorithm, macBuffer} = await this.constructor.createMac(request.assoc_type);

      if (!macBuffer) {
        return this.unsupportedAssociation(res, 'Association type not recognised: ' + request.assoc_type);
      }

      const dh = crypto.createDiffieHellman(request.dh_modulus || DH_MODULUS_ENCODED, 'base64');
      const publicKeyBase64 = this.constructor.btwoc(dh.generateKeys()).toString('base64');
      const secretKeyBinary = dh.computeSecret(request.dh_consumer_public, 'base64');
      const hash = crypto.createHash(hashAlgorithm);

      hash.update(this.constructor.btwoc(secretKeyBinary));

      const association = new Association(hashAlgorithm, macBuffer.toString('base64'), this.associationExpirySecs, false);
      const encodedMac = this.constructor.xor(hash.digest(), macBuffer);

      await this.associationStore.put(association);

      /* eslint-disable id-match */
      const response = {
        assoc_handle: association.handle,
        assoc_type: request.assoc_type,
        dh_server_public: publicKeyBase64,
        enc_mac_key: encodedMac.toString('base64'),
        expires_in: this.associationExpirySecs,
        session_type: request.session_type
      };
      /* eslint-enable id-match */

      return this.constructor.sendDirectResponse(res, response);
    } catch (error) {
      return this.constructor.internalError(error, res, next);
    }
  }

  async checkAuthentication (request, req, res, next) {
    const sendError = () => this.constructor.sendDirectResponse(res, {
      // eslint-disable-next-line id-match
      is_valid: 'false'
    });

    if (!request.assoc_handle || !request.response_nonce) {
      return sendError();
    }
    try {
      const nonce = await this.nonceStore.getAndDelete(request.response_nonce);

      if (!nonce) {
        return sendError();
      }

      // TODO - should check nonce expiry
      try {
        const association = await this.associationStore.get(request.assoc_handle);

        if (!association || !association.private) {
          return sendError();
        }

        if (association.expiry < Date.now()) {
          try {
            await this.associationStore.delete(request.assoc_handle);

            return sendError();
          } catch (error) {
            return this.constructor.internalError(error, res, next);
          }
        }

        // If the mode is signed, it needs the same value as previously
        request.mode = 'id_res';

        const hmac = crypto.createHmac(association.algorithm, Buffer.from(association.secret, 'base64'));
        const message = messageFactory.toForm(request, request.signed.split(/,/));

        hmac.update(message.body);

        const sig = hmac.digest('base64');

        return this.constructor.sendDirectResponse(res, {
          // eslint-disable-next-line id-match
          is_valid: sig === request.sig
        });
      } catch (error) {
        return this.constructor.internalError(error, res, next);
      }
    } catch (error) {
      return this.constructor.internalError(error, res, next);
    }
  }

  // 4.2
  static btwoc (buffer) {
    // if the most significant byte doesn't have it's most significant bit set, we're good
    if (buffer[0] <= 127) {
      return buffer;
    }

    // make a new buffer which is a copy of the old with an extra 0x00 on the front
    const result = Buffer.from(buffer.length + 1);

    result[0] = 0;
    buffer.copy(result, 1);

    return result;
  }

  static xor (bufa, bufb) {
    const result = Buffer.from(bufa.length);

    for (let index = 0; index < bufa.length; index++) {
      result[index] = bufa[index] ^ bufb[index];
    }

    return result;
  }

  static sendIndirectResponseError (request, res, message) {
    // 5.2.3
    const response = {
      error: message,
      mode: 'error'
    };

    this.sendIndirectResponse(request, res, response);
  }

  static sendIndirectResponse (request, res, response) {
    if (!request.return_to || !isWebUri(request.return_to)) {
      // No return_to, or not a valid URL.
      return res.send(400, 'Invalid return_to parameter');
    }

    // TODO some or all of this belongs in messageFactory

    // 5.2.3
    const returnToUrl = url.parse(request.return_to, true);

    returnToUrl.query['openid.ns'] = OPENID_NS;
    for (const field of Object.keys(response)) {
      // 4.1.3
      returnToUrl.query['openid.' + field] = response[field];
    }
    delete returnToUrl.search;

    // 5.2.1
    return res.redirect(302, url.format(returnToUrl));
  }

  static sendDirectResponseError (res, response) {
    // 5.1.2.2
    res.status(400);
    this.sendDirectResponse(res, response);
  }

  static sendDirectResponse (res, response) {
    // 5.1.2
    res.type('text/plain');
    res.send(messageFactory.toForm(response).body);
  }

  static internalError (err, res, next) {
    // Return a 500 to the caller and pass the error to the Express error handler
    res.type('text/plain');
    res.send(500, err.message || err);

    return next ? next(err) : null;
  }

  static async createMac (assocType) {
    switch (assocType) {
    case 'HMAC-SHA1': {
      const macBuffer = await randomBytesAsync(20);

      return {
        hashAlgorithm: 'sha1',
        macBuffer
      };
    }
    case 'HMAC-SHA256': {
      const macBuffer = await randomBytesAsync(32);

      return {
        hashAlgorithm: 'sha256',
        macBuffer
      };
    }
    default: return Promise.resolve();
    }
  }
}

module.exports = OpenIDProvider;
