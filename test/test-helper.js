var express = require('express'),
    Skylith = require('../skylith'),
    endpoint = 'http://localhost:3030/openid',  // This doesn't have to be real!
    skylith = new Skylith({ providerEndpoint: endpoint, checkAuth: checkAuth }),
    app = express();

var currentCheckAuth;

// app.use('/', function(req, res, next) {
//     console.log(req.method, req.url);
//     next();
// });

app.use('/openid', skylith.express());

exports = module.exports = {
    endpoint: endpoint,
    app: app,
    setCheckAuth: function(checkAuth) { currentCheckAuth = checkAuth; }
}

function checkAuth() {
    var args = Array.prototype.slice.call(arguments);
    currentCheckAuth.call(null, args);
}
