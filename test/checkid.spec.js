const testHelper = require('./test-helper');

const openIdFields = testHelper.openIdFields;
const checkAuth = testHelper.checkAuth;

describe('checkid_setup/checkid_immediate: main flow', () => {
  ['get', 'post'].forEach((verb) => {
    it('successful checkid_setup with ' + verb.toUpperCase(), (done) => {
      testHelper[verb]('/openid', {
        mode: 'checkid_setup',
        realm: 'http://localhost/',
        // eslint-disable-next-line id-match
        return_to: 'http://localhost/here'
      })
        .expect(302)
        .expect(checkAuth({
          ensureInteractive: true,
          identity: 'bob@example.com'
        }))
        .expect(openIdFields({
          // eslint-disable-next-line id-match
          claimed_id: testHelper.identity('bob@example.com'),
          identity: testHelper.identity('bob@example.com'),
          mode: 'id_res'
        }))
        .end(done);
    });

    it('cancelled checkid_setup with ' + verb.toUpperCase(), (done) => {
      testHelper[verb]('/openid', {
        mode: 'checkid_setup',
        realm: 'http://localhost/',
        // eslint-disable-next-line id-match
        return_to: 'http://localhost/here'
      })
        .expect(302)
        .expect(checkAuth({
          ensureInteractive: true,
          identity: 'bob@example.com',
          succeed: false
        }))
        .expect(openIdFields({
          mode: 'cancel'
        }))
        .end(done);
    });

    it('successful checkid_immediate with ' + verb.toUpperCase(), (done) => {
      testHelper[verb]('/openid', {
        mode: 'checkid_immediate',
        realm: 'http://localhost/',
        // eslint-disable-next-line id-match
        return_to: 'http://localhost/here'
      })
        .expect(302)
        .expect(checkAuth({
          ensureInteractive: false,
          identity: 'bob@example.com'
        }))
        .expect(openIdFields({
          // eslint-disable-next-line id-match
          claimed_id: testHelper.identity('bob@example.com'),
          identity: testHelper.identity('bob@example.com'),
          mode: 'id_res'
        }))
        .end(done);
    });

    it('cancelled checkid_immediate with ' + verb.toUpperCase(), (done) => {
      testHelper[verb]('/openid', {
        mode: 'checkid_immediate',
        realm: 'http://localhost/',
        // eslint-disable-next-line id-match
        return_to: 'http://localhost/here'
      })
        .expect(302)
        .expect(checkAuth({
          ensureInteractive: false,
          identity: 'bob@example.com',
          succeed: false
        }))
        .expect(openIdFields({
          mode: 'setup_needed'
        }))
        .end(done);
    });
  });
});
