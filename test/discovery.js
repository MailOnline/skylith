let util = require('util'),
  cheerio = require('cheerio'),
  chai = require('chai'),
  assert = chai.assert;

let testHelper = require('./test-helper'),
  endpoint = testHelper.endpoint;

describe('Discovery', () => {
  describe('XRDS', () => {
    it('returns server document', (done) => {
      testHelper
        .get('/openid')
        .accept('application/xrds+xml')
        .expect(200, getExpectedXRDSDocument('server'))
        .expect('Content-Type', 'application/xrds+xml')
        .end(done);
    });

    it('returns user document', (done) => {
      testHelper
        .get('/openid?u=charlie')
        .accept('application/xrds+xml')
        .expect(200, getExpectedXRDSDocument('signon'))
        .expect('Content-Type', 'application/xrds+xml')
        .end(done);
    });
  });

  describe('HTML', () => {
    it('returns server document', (done) => {
      testHelper
        .get('/openid')
        .accept('text/html')
        .expect(200)
        .expect('Content-Type', 'text/html')
        .expect((res) => {
          const $ = cheerio.load(res.text);

          assert.equal($('html>head>link[rel="openid2.provider"]').attr('href'), testHelper.endpoint);
          assert.equal($('html>head>link[rel="openid2.local_id"]').length, 0);
        })
        .end(done);
    });

    it('returns user document', (done) => {
      testHelper
        .get('/openid?u=charlie')
        .accept('text/html')
        .expect(200)
        .expect('Content-Type', 'text/html')
        .expect((res) => {
          const $ = cheerio.load(res.text);

          assert.equal($('html>head>link[rel="openid2.provider"]').attr('href'), testHelper.endpoint);
          assert.equal($('html>head>link[rel="openid2.local_id"]').attr('href'), testHelper.identity('charlie'));
        })
        .end(done);
    });
  });

  it('rejects unknown content types', (done) => {
    testHelper
      .get('/openid?u=charlie')
      .accept('application/json')
      .expect(406)
      .end(done);
  });
});

const XRDSTemplate = `<?xml version="1.0" encoding="UTF-8"?>
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

function getExpectedXRDSDocument (type) {
  return util.format(XRDSTemplate, type, endpoint);
}
