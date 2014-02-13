var chai = require('chai'),
    assert = chai.assert;

var testHelper = require('./test-helper'),
    endpoint = testHelper.endpoint,
    openIdFields = testHelper.openIdFields,
    checkAuth = testHelper.checkAuth;

describe('Login', function() {

    ['get', 'post'].forEach(function(verb) {
        it('checkid_setup with ' + verb.toUpperCase(), function(done) {
            testHelper[verb]('/openid', {
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
                    mode: 'id_res',
                    claimed_id: testHelper.identity('bob@example.com'),
                    identity: testHelper.identity('bob@example.com')
                }))
                .end(done);
        });
    });
});

