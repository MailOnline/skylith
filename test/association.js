var chai = require('chai'),
    assert = chai.assert;

var testHelper = require('./test-helper'),
    endpoint = testHelper.endpoint,
    openIdFields = testHelper.openIdFields,
    checkAuth = testHelper.checkAuth;

describe('Association: main flow', function() {
    ['HMAC-SHA1', 'HMAC-SHA256'].forEach(function(associationType) {
        ['DH-SHA1', 'DH-SHA256'].forEach(function(sessionType) {
            it('Create association with ' + associationType + '/' + sessionType, function(done) {
                var DH_MODULUS_HEX = 'DCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E' +
                                     'F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557' +
                                     '7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382' +
                                     '6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB';

                var crypto = require('crypto'),
                    dh = crypto.createDiffieHellman(DH_MODULUS_HEX, 'hex'),
                    consumer_public = dh.generateKeys('base64');

                testHelper.post('/openid', {
                        mode: 'associate',
                        assoc_type: associationType,
                        session_type: sessionType,
                        dh_consumer_public: consumer_public
                    })
                    .expect(200)
                    .end(done);
            });
        });

        // add tests for unencypted sessions
        // HTTP
        // HTTPS
    });
});
