var chai = require('chai'),
    assert = chai.assert;

var testHelper = require('./test-helper'),
    endpoint = testHelper.endpoint,
    openIdFields = testHelper.openIdFields,
    checkAuth = testHelper.checkAuth;

describe('Login', function() {
    ['get', 'post'].forEach(function(verb) {
        it('successful checkid_setup with ' + verb.toUpperCase(), function(done) {
            testHelper[verb]('/openid', {
                    mode: 'checkid_setup',
                    realm: 'http://localhost/',
                    return_to: 'http://localhost/here'
                })
                .expect(302)
                .expect(checkAuth({
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

        it('cancelled checkid_setup with ' + verb.toUpperCase(), function(done) {
        testHelper[verb]('/openid', {
                mode: 'checkid_setup',
                realm: 'http://localhost/',
                return_to: 'http://localhost/here'
            })
            .expect(302)
            .expect(checkAuth({
                succeed: false,
                identity: 'bob@example.com',
                ensureInteractive: true
            }))
            .expect(openIdFields({
                mode: 'cancel'
            }))
            .end(done);
        });

        it('successful checkid_immediate with ' + verb.toUpperCase(), function(done) {
            testHelper[verb]('/openid', {
                    mode: 'checkid_immediate',
                    realm: 'http://localhost/',
                    return_to: 'http://localhost/here'
                })
                .expect(302)
                .expect(checkAuth({
                    identity: 'bob@example.com',
                    ensureInteractive: false
                }))
                .expect(openIdFields({
                    mode: 'id_res',
                    claimed_id: testHelper.identity('bob@example.com'),
                    identity: testHelper.identity('bob@example.com')
                }))
                .end(done);
        });

        it('cancelled checkid_immediate with ' + verb.toUpperCase(), function(done) {
            testHelper[verb]('/openid', {
                mode: 'checkid_immediate',
                realm: 'http://localhost/',
                return_to: 'http://localhost/here'
            })
            .expect(302)
            .expect(checkAuth({
                succeed: false,
                identity: 'bob@example.com',
                ensureInteractive: false
            }))
            .expect(openIdFields({
                mode: 'setup_needed'
            }))
            .end(done);
        });
    });
});

