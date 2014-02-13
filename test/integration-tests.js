var util = require('util'),
    chai = require('chai'),
    assert = chai.assert;

var testHelper = require('./test-helper'),
    endpoint = testHelper.endpoint,
    openIdFields = testHelper.openIdFields,
    checkAuth = testHelper.checkAuth;

describe('Skylith', function() {
    describe('discovery', function() {
        it('returns server XRDS document', function(done) {
            testHelper
                .get('/openid')
                .set('Accept', 'application/xrds+xml')
                .expect(200, getExpectedXRDSDocument('server'))
                .end(done);
        });

        it('returns user XRDS document', function(done) {
            testHelper
                .get('/openid?u=charlie')
                .set('Accept', 'application/xrds+xml')
                .expect(200, getExpectedXRDSDocument('signon'))
                .end(done);
        });

        it.skip('returns server HTML document', function(done) {
        });

        it.skip('returns user HTML document', function(done) {
        });
    });

    describe('login', function() {
        it('checkid_setup with GET', function(done) {
            testHelper
                .get('/openid', {
                    mode: 'checkid_setup',
                    realm: 'http://localhost/',
                    return_to: 'http://localhost/here'
                })
                .expect(302)
                .expect(checkAuth({
                    succeed: true,
                    identity: 'bob@example.com',
                    ensureInteractive: true
                }))
                .expect(openIdFields({
                    'mode': 'id_res',
                    'claimed_id': endpoint + '?u=' + encodeURIComponent('bob@example.com'),
                    'identity': endpoint + '?u=' + encodeURIComponent('bob@example.com')
                }))
                .end(done);
        });
    });
});

var XRDSTemplate = '<?xml version="1.0" encoding="UTF-8"?>' +
                   '<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">' +
                   '<XRD>' +
                   '<Service priority="0">' +
                   '<Type>http://specs.openid.net/auth/2.0/%s</Type>' +
                   '<Type>http://openid.net/srv/ax/1.0</Type>' +
                   '<URI>%s</URI>' +
                   '</Service>' +
                   '</XRD>' +
                   '</xrds:XRDS>';

function getExpectedXRDSDocument(type) {
    return util.format(XRDSTemplate, type, endpoint);
}
