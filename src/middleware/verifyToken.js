const config = require('../../routes/config.js');
const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
  const token = req.headers['x-access-token'];

  if (!token) {
    return res.status(401).json({
      auth: false,
      errorMessage: 'No token provided',
    });
  } else {
    jwt.verify(token, config.secret, function (error) {
      if (error) {
        res.status(401).json({
          auth: false,
          errorMessage: 'Invalid token',
        });
      } else next();
    });
  }
}

module.exports = verifyToken;
