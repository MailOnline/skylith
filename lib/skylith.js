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
    util = require('util'),
    Request = require('./request'),
    Association = require('./association'),
    MemoryAssociationStore = require('./memoryAssociationStore');

var PROVIDER_ENDPOINT = 'http://localhost:3000/'; // TODO
var DEFAULT_ASSOCIATION_EXPIRY = 1; // TODO

var DH_MODULUS_HEX = 'DCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E' +
                     'F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557' +
                     '7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382' +
                     '6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB';

var DH_MODULUS_B64 = new Buffer(DH_MODULUS_HEX, 'hex').toString('base64');

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

function OpenIDProvider(options) {
    if (!(this instanceof OpenIDProvider)) {
        return new OpenIDProvider(options);
    }

    var self = this;
    var associationStore = new MemoryAssociationStore();  // TODO

    this.express = function() {
        return middleware;
    }

    this.providerEndpoint = function() {
        return PROVIDER_ENDPOINT;
    }

    this.sendHtmlDiscoveryResponse = function(req, res, next) {
        res.type('html');
        res.end(util.format(HTML_DISCOVERY_RESPONSE_TEMPLATE, this.providerEndpoint()));
    }

    function middleware(req, res, next) {
        if (req.body['openid.ns'] !== 'http://specs.openid.net/auth/2.0') return next(); // not OpenID (4.1.2)

        var request = new Request(req);

        if (req.method === 'POST' && request.mode === 'associate') {  // 8.1
            return associate(request, res, next);
        }

        if (req.method === 'POST') {
            // unknown direct request
            // 5.1.2.2
            sendDirectResponseError(res, {
                error: 'Unknown or unsupported direct request'
            });
            return;
        }
        next();
    }

    function associate(request, res, next) {
        if (request.session_type === 'no-encryption') {
            if (request.httpReq().secure) {
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
            if (err) return internalError(err);
            if (!macBuffer) return unsupportedAssociation(res, 'Association type not recognised: ' + request.assoc_type);

            var association = new Association(hashAlgorithm, macBuffer.toString('base64'));

            associationStore.put(association, function(err) {
                if (err) return internalError(err, res, next);

                var response = {
                    assoc_handle: association.handle,
                    session_type: request.session_type,
                    assoc_type: request.assoc_type,
                    expires_in: DEFAULT_ASSOCIATION_EXPIRY,
                    mac_key: macBuffer.toString('base64')
                }

                sendDirectResponse(res, response);
            });
        });
    }

    function diffieHellmanAssociate(request, res, dhHash, next) {
        createMac(request.assoc_type, function(err, macBuffer, hashAlgorithm) {
            if (err) return internalError(err);
            if (!macBuffer) return unsupportedAssociation(res, 'Association type not recognised: ' + request.assoc_type);

            var dh = crypto.createDiffieHellman(request.dh_modulus || DH_MODULUS_B64, 'base64');
            var publicKeyBase64 = dh.generateKeys('base64');
            var secretKeyBinary = dh.computeSecret(request.dh_consumer_public, 'base64');
            var hash = crypto.createHash(hashAlgorithm);

            hash.update(btwoc(secretKeyBinary));

            var association = new Association(hashAlgorithm, macBuffer.toString('base64'));
            var encodedMac = xor(hash.digest(), macBuffer);

            associationStore.put(association, function(err) {
                if (err) return internalError(err, res, next);

                var response = {
                    assoc_handle: association.handle,
                    session_type: request.session_type,
                    assoc_type: request.assoc_type,
                    expires_in: DEFAULT_ASSOCIATION_EXPIRY,
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

    function sendDirectResponseError(res, response) {
        res.status(400);   // 5.1.2.2
        sendDirectResponse(res, response);
    }

    // 4.1.1
    function sendDirectResponse(res, response) {
        var body = 'ns:http://specs.openid.net/auth/2.0';  // 5.1.2

        for (var field in response) {
            body = body + '\n' + field + ':' + response[field];
        }

        res.type('text/plain');  // 5.1.2
        res.send(body);
    }

    function internalError(err, res, next) {
        // Return a 500 to the caller and pass the error to the Express error handler
        res.type('text/plain');
        res.send(500, err.message || err);
        next(err);
    }
}

exports = module.exports = OpenIDProvider;
