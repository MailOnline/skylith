var testHelper = require('./test-helper'),
    isDelegated = testHelper.isDelegated,
    error = testHelper.error;

describe('Middleware', function() {
    it('delegates non-OpenId POST requests', function(done) {
        testHelper.post('/openid')
            .expect(404)
            .expect(isDelegated())
            .end(done);
    });

    it('delegates non-OpenId GET requests which are not discovery', function(done) {
        testHelper.get('/openid/login')  // Discovery is assumed for all GETs on the mount point
            .expect(404)
            .expect(isDelegated())
            .end(done);
    });

    it('sends a direct error response for unrecognised POST requests', function(done) {
        testHelper.post('/openid', {
                mode: 'badmode'
            })
            .expect(error('Unknown or unsupported direct request'))
            .end(done);
    });

    it('sends an indirect error response for unrecognised GET requests', function(done) {
        testHelper.get('/openid', {
                mode: 'badmode',
                return_to: 'http://localhost/here'
            })
            .expect(error('Unknown or unsupported indirect request'))
            .end(done);
    });
});
