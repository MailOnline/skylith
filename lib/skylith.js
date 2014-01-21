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

var crypto = require('crypto'),
    url = require('url'),
    util = require('util'),
    validUrl = require('valid-url'),
    uri = require('uri-js'),
    messageFactory = require('./messageFactory'),
    Association = require('./association'),
    MemoryAssociationStore = require('./memoryAssociationStore'),  // TODO
    MemoryNonceStore = require('./memoryNonceStore');  // TODO

// TODO: These should all be configurable by the client
var PROVIDER_ENDPOINT = 'http://localhost:3000/'; // TODO
var DEFAULT_ASSOCIATION_EXPIRY_SECS = 30; // TODO
var DEFAULT_NONCE_EXPIRY_SECS = 30; // TODO
var COOKIE = 'oidp'; // TODO
var LOGIN_URL = url.resolve(PROVIDER_ENDPOINT, 'login'); // TODO

var DH_MODULUS_HEX = 'DCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E' +
                     'F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557' +
                     '7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382' +
                     '6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB';

var DH_MODULUS_B64 = new Buffer(DH_MODULUS_HEX, 'hex').toString('base64');

var OPENID_NS = 'http://specs.openid.net/auth/2.0';  // TODO duplicated

var HTML_DISCOVERY_RESPONSE_TEMPLATE = '<!DOCTYPE html>\
<html>\
<head>\
<title>OpenID Provider</title>\
<link rel="openid2.provider" href="%s">\
</head>\
<body>\
</body>\
</html>\
';

var HTML_VALIDATION_RESPONSE_TEMPLATE = '<!DOCTYPE html>\
<html>\
<head>\
<title>OpenID Provider</title>\
<link rel="openid2.provider" href="%s">\
<link rel="openid2.local_id" href="%s">\
</head>\
<body>\
</body>\
</html>\
';

var XRDS_DISCOVERY_RESPONSE_TEMPLATE = '<?xml version="1.0" encoding="UTF-8"?>\
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">\
<XRD>\
<Service priority="0">\
<Type>http://specs.openid.net/auth/2.0/%s</Type>\
<URI>%s</URI>\
</Service>\
</XRD>\
</xrds:XRDS>\
';

function OpenIDProvider(options) {
    if (!(this instanceof OpenIDProvider)) {
        return new OpenIDProvider(options);
    }

    var self = this;
    var associationStore = new MemoryAssociationStore();  // TODO
    var nonceStore = new MemoryNonceStore();  // TODO

    this.express = function() {
        return middleware;
    }

    this.providerEndpoint = function() {
        return PROVIDER_ENDPOINT;
    }

    this.sendDiscoveryResponse = function(req, res, user, next) {
        if (typeof user === 'function') {
            next = user;
            user = undefined;
        }

        if (req.accepts('application/xrds+xml')) {
            res.type('application/xrds+xml');

            if (user) {
                res.end(util.format(XRDS_DISCOVERY_RESPONSE_TEMPLATE, 'signon', this.providerEndpoint()));
            } else {
                res.end(util.format(XRDS_DISCOVERY_RESPONSE_TEMPLATE, 'server', this.providerEndpoint()));
            }
        } else if (req.accepts('text/html')) {
            res.type('text/html');

            if (user) {
                res.end(util.format(HTML_VALIDATION_RESPONSE_TEMPLATE, this.providerEndpoint(), localId(user)));
            } else {
                res.end(util.format(HTML_DISCOVERY_RESPONSE_TEMPLATE, this.providerEndpoint()));
            }
        } else {
            next();
        }
    }

    this.completeAuth = function(req, res, username, next) {
        checkIdSetupComplete(req, res, username, next);
    }

    function middleware(req, res, next) {
        if (req.method === 'POST') {
            var request = messageFactory.fromBody(req);

            if (request.ns !== OPENID_NS) return next(); // not OpenID (4.1.2)

            if (request.mode === 'associate') {  // 8.1
                return associate(request, req, res, next);
            }

            if (request.mode === 'check_authentication') {  // 11.4.2.1
                return checkAuthentication(request, req, res, next);
            }

            if (request.mode === 'checkid_setup') {  // checkid_setup can be posted
                return checkIdSetup(request, res, next);
            }

            // unknown direct request
            sendDirectResponseError(res, {
                error: 'Unknown or unsupported direct request'
            });
        } else if (req.method === 'GET') {
            var request = messageFactory.fromQueryArgs(req);

            if (request.ns !== OPENID_NS) return next(); // not OpenID (4.1.2)

            if (request.mode === 'checkid_setup') {
                return checkIdSetup(request, res, next);
            }

            // unknown indirect request
            sendIndirectResponseError(request, res, 'Unknown or unsupported indirect request');
        } else {
            next();
        }
    }

    function associate(request, req, res, next) {
        if (request.session_type === 'no-encryption') {
            if (req.secure) {
                unencryptedAssociation(request, res, next);
            } else {
                // 8.1.1, 8.4.1
                unsupportedAssociation(res, 'Cannot create a "no-encryption" session without using HTTPS');
            }
        } else if (request.session_type === 'DH-SHA1') {
            diffieHellmanAssociate(request, res, 'sha1', next);
        } else if (request.session_type === 'DH-SHA256') {
            diffieHellmanAssociate(request, res, 'sha256', next);
        } else {
            unsupportedAssociation(res, 'Session type not recognised: ' + request.session_type);
        }
    }

    function unencryptedAssociation(request, res, next) {
        createMac(request.assoc_type, function(err, macBuffer, hashAlgorithm) {
            if (err) return internalError(err, res, next);
            if (!macBuffer) return unsupportedAssociation(res, 'Association type not recognised: ' + request.assoc_type);

            var association = new Association(hashAlgorithm, macBuffer.toString('base64'), DEFAULT_ASSOCIATION_EXPIRY_SECS, false);

            associationStore.put(association, function(err) {
                if (err) return internalError(err, res, next);

                var response = {
                    assoc_handle: association.handle,
                    session_type: request.session_type,
                    assoc_type: request.assoc_type,
                    expires_in: DEFAULT_ASSOCIATION_EXPIRY_SECS,
                    mac_key: macBuffer.toString('base64')
                }

                sendDirectResponse(res, response);
            });
        });
    }

    function diffieHellmanAssociate(request, res, dhHash, next) {
        createMac(request.assoc_type, function(err, macBuffer, hashAlgorithm) {
            if (err) return internalError(err, res, next);
            if (!macBuffer) return unsupportedAssociation(res, 'Association type not recognised: ' + request.assoc_type);

            var dh = crypto.createDiffieHellman(request.dh_modulus || DH_MODULUS_B64, 'base64');
            var publicKeyBase64 = dh.generateKeys('base64');
            var secretKeyBinary = dh.computeSecret(request.dh_consumer_public, 'base64');
            var hash = crypto.createHash(hashAlgorithm);

            hash.update(btwoc(secretKeyBinary));

            var association = new Association(hashAlgorithm, macBuffer.toString('base64'), DEFAULT_ASSOCIATION_EXPIRY_SECS, false);
            var encodedMac = xor(hash.digest(), macBuffer);

            associationStore.put(association, function(err) {
                if (err) return internalError(err, res, next);

                var response = {
                    assoc_handle: association.handle,
                    session_type: request.session_type,
                    assoc_type: request.assoc_type,
                    expires_in: DEFAULT_ASSOCIATION_EXPIRY_SECS,
                    dh_server_public: publicKeyBase64,
                    enc_mac_key: encodedMac.toString('base64')
                }

                sendDirectResponse(res, response);
            });
        });
    }

    function createMac(assocType, next) {
        if (assocType === 'HMAC-SHA1') {
            crypto.randomBytes(20, function(err, buffer) {
                next(err, buffer, 'sha1');
            });
        } else if (assocType === 'HMAC-SHA256') {
            crypto.randomBytes(32, function(err, buffer) {
                next(err, buffer, 'sha256');
            });
        } else {
            next();  // pass undefined buffer back to caller
        }
    }

    function unsupportedAssociation(res, message) {
        // 8.2.4
        sendDirectResponseError(res, {
            error: message,
            error_code: 'unsupported-type',
            session_type: 'DH-SHA256',
            assoc_type: 'HMAC-SHA256'
        });
    }

    // 4.2
    function btwoc(buffer) {
        // if the most significant byte doesn't have it's most significant bit set, we're good
        if (buffer[0] <= 127) return buffer;

        // make a new buffer which is a copy of the old with an extra 0x00 on the front
        var result = new Buffer(buffer.length + 1);
        result[0] = 0;
        buffer.copy(result, 1);
        return result;
    }

    function xor(a, b) {
        var result = new Buffer(a.length);

        for (var i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        };

        return result;
    }

    function checkIdSetup(request, res, message) {
        if (!request.return_to && !request.realm) {
            return sendIndirectResponseError(request, res, 'checkid_setup must specify one (or both) of return_to and realm');  // 9.1
        }

        if (request.realm) {
            var wildcardRealm = false;

            // Validate realm. 9.2
            var parsedRealm = uri.parse(request.realm);  // Use a third-party parser instead of the node URL module to get wildcard support

            if (parsedRealm.errors.length > 0) return sendIndirectResponseError(request, res, 'Invalid realm');

            if (parsedRealm.fragment) return sendIndirectResponseError(request, res, 'Realm cannot contain a fragment');

            if (parsedRealm.host.slice(0, 2) === '*.') {
                // replace the wildcard realm with a non-wildcard
                parsedRealm.host = parsedRealm.host.slice(2);
                wildcardRealm = true;
            }

            parsedRealm = uri.normalize(parsedRealm);

            // Now revalidate with something that specifically understands HTTP and HTTPS URLs (instead of general URIs)
            if (!validUrl.isWebUri(uri.serialize(parsedRealm))) return sendIndirectResponseError(request, res, 'Invalid realm');

            if (request.return_to) {
                var parsedReturnTo = uri.normalize(uri.parse(request.return_to));

                // The schemes and ports must be equal
                if (parsedRealm.scheme !== parsedReturnTo.scheme || parsedRealm.port !== parsedReturnTo.port) {
                    return sendIndirectResponseError(request, res, 'The return_to URL does not match the realm');
                }

                // The pathnames must be equal or else the return_to pathname must be a "sub-directory" of the realm pathname. 9.2
                if (!(parsedRealm.pathname === parsedReturnTo.pathname || parsedReturnTo.pathname.indexOf(parsedRealm.pathname + '/') === 0)) {
                    return sendIndirectResponseError(request, res, 'The return_to URL does not match the realm');
                }

                // Hostnames match or the return_to hostname must END with '.'+realm hostname IFF realm was wildcarded
                if (!(parsedRealm.hostname === parsedReturnTo.hostname ||
                     (wildcardRealm && parsedReturnTo.hostname.substr(parsedReturnTo.hostname.length - parsedRealm.hostname.length - 1) === '.' + parsedRealm.hostname))) {
                    return sendIndirectResponseError(request, res, 'The return_to URL does not match the realm');
                }
            }
        }

        // TODO: check if already logged in

        res.cookie(COOKIE, request, {
            signed: true,
            maxAge: 5 * 60 * 1000   // 5 mins
        });

        res.redirect(302, LOGIN_URL);
    }

    function checkIdSetupComplete(req, res, username, next) {
        var request = req.signedCookies[COOKIE],
            association,
            nonce = {
                id: new Date().toISOString().slice(0, -5) + 'Z' + crypto.randomBytes(4).toString('hex'),
                expiry: Date.now() + (DEFAULT_NONCE_EXPIRY_SECS * 1000)
            },
            response = {
                mode: 'id_res',
                op_endpoint: PROVIDER_ENDPOINT,
                claimed_id: localId(username),
                identity: localId(username),
                return_to: request.return_to,
                response_nonce: nonce.id
            };

        if (!request) return res.send(404);

        // Cookie is signed, so shouldn't be tampered with. Do some basic checks just to be sure.
        if (request.ns !== OPENID_NS || request.mode !== 'checkid_setup') return sendIndirectResponseError('Cookie tampering! Oh my!');

        function checkAssociation() {
            var deleteHandle;

            if (request.assoc_handle) {
                associationStore.get(request.assoc_handle, function(err, a) {
                    if (err) return internalError(err, res, next);

                    var remove = false;

                    association = a;

                    if (association && association.expires < Date.now()) {
                        // Association expired
                        remove = true;
                        association = undefined;  // Proceed as if no handle specified. s10
                    }

                    if (!association) {
                        // Not found or expired
                        response.invalidate_handle = request.assoc_handle;
                    }

                    if (remove) {
                        associationStore.delete(request.assoc_handle, function(err) {
                            if (err) return internalError(err, res, next);

                            privateAssociation();
                        });
                    } else {
                        privateAssociation();
                    }
                });
            } else {
                privateAssociation();
            }
        }

        function privateAssociation() {
            if (!association) {
                // Make a "private association". The spec is vague here. For example, how do we know the client supports the algorithm we choose?
                createMac('HMAC-SHA256', function(err, macBuffer, hashAlgorithm) {
                    if (err) return internalError(err, res, next);

                    association = new Association(hashAlgorithm, macBuffer.toString('base64'), DEFAULT_ASSOCIATION_EXPIRY_SECS, true);

                    associationStore.put(association, function(err) {
                        if (err) return internalError(err, res, next);

                        signResponse();
                    });
                });
            } else {
                signResponse();
            }
        }

        function signResponse() {
            response.assoc_handle = association.handle;

            var hmac = crypto.createHmac(association.algorithm, new Buffer(association.secret, 'base64'));
            var message = messageFactory.toForm(response);

            hmac.update(message.body);

            response.sig = hmac.digest('base64');
            response.signed = message.fields.join(',');

            sendResponse();
        }

        function sendResponse() {
            nonceStore.put(nonce, function(err) {
                if (err) return internalError(err, res, next);
                sendIndirectResponse(request, res, response);
            });
        }

        checkAssociation();
    }

    function checkAuthentication(request, req, res, next) {
        function error() {
            sendDirectResponse(res, {
                is_valid: 'false'
            });
        }

        if (!request.assoc_handle) return error();
        if (!request.response_nonce) return error();

        nonceStore.getAndDelete(request.response_nonce, function(err, nonce) {
            if (err) return internalError(err, res, next);

            if (!nonce) return error();

            associationStore.get(request.assoc_handle, function(err, association) {
                if (err) return internalError(err, res, next);

                if (!association) return error();
                if (!association.private) return error();

                if (association.expires < Date.now()) {
                    associationStore.delete(request.assoc_handle, function(err) {
                        if (err) return internalError(err, res, next);

                        return error();
                    });
                }

                request.mode = 'id_res';  // If the mode is signed, it needs the same value as previously

                var hmac = crypto.createHmac(association.algorithm, new Buffer(association.secret, 'base64'));
                var message = messageFactory.toForm(request, request.signed.split(/,/));

                hmac.update(message.body);

                var sig = hmac.digest('base64');

                sendDirectResponse(res, {
                    is_valid: sig === request.sig
                });
            });
        });
    }

    function sendIndirectResponseError(request, res, message) {
        // 5.2.3
        var response = {
            mode: 'error',
            error: message
        }

        sendIndirectResponse(request, res, response);
    }

    function sendIndirectResponse(request, res, response) {
        if (!request.return_to || !validUrl.isWebUri(request.return_to)) {
            // No return_to, or not a valid URL.
            return res.send(400);
        }

        // TODO some or all of this belongs in messageFactory

        var returnToUrl = url.parse(request.return_to, true);  // 5.2.3

        returnToUrl.query['openid.ns'] = OPENID_NS;
        for (var field in response) {
            // 4.1.3
            returnToUrl.query['openid.' + field] = response[field];
        }
        delete returnToUrl.search;

        res.redirect(302, url.format(returnToUrl));  // 5.2.1
    }

    function sendDirectResponseError(res, response) {
        // 5.1.2.2
        res.status(400);
        sendDirectResponse(res, response);
    }

    function sendDirectResponse(res, response) {
        res.type('text/plain');  // 5.1.2
        res.send(messageFactory.toForm(response).body);
    }

    function internalError(err, res, next) {
        // Return a 500 to the caller and pass the error to the Express error handler
        res.type('text/plain');
        res.send(500, err.message || err);
        next(err);
    }

    function localId(username) {
        return url.resolve(PROVIDER_ENDPOINT, 'users/' + username.toLowerCase())
    }
}

exports = module.exports = OpenIDProvider;
