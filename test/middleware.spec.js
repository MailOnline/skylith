const testHelper = require('./test-helper');

const isDelegated = testHelper.isDelegated;
const error = testHelper.error;

describe('Middleware', () => {
  it('delegates non-OpenId POST requests', (done) => {
    testHelper.post('/openid')
      .expect(404)
      .expect(isDelegated())
      .end(done);
  });

  it('delegates non-OpenId GET requests which are not discovery', (done) => {
    // Discovery is assumed for all GETs on the mount point
    testHelper.get('/openid/login')
      .expect(404)
      .expect(isDelegated())
      .end(done);
  });

  it('sends a direct error response for unrecognised POST requests', (done) => {
    testHelper.post('/openid', {
      mode: 'badmode'
    })
      .expect(error('Unknown or unsupported direct request'))
      .end(done);
  });

  it('sends an indirect error response for unrecognised GET requests', (done) => {
    testHelper.get('/openid', {
      mode: 'badmode',
      // eslint-disable-next-line id-match
      return_to: 'http://localhost/here'
    })
      .expect(error('Unknown or unsupported indirect request'))
      .end(done);
  });
});
