// JWT misconfig fixture for Suzaku Compass tests.

const jwt = require('jsonwebtoken');

function verifyNone(token, key) {
  return jwt.verify(token, key, { algorithms: ['none'] });
}

function rs256ToHs256Confusion(token, pub) {
  return jwt.verify(token, pub.publicKey);  // no algorithms whitelist
}

const JWT_SECRET = "abc";  // weak secret
