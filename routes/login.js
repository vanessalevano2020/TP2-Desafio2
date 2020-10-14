let express = require('express');
let router = express.Router();
const config = require('./config.js');
const jwt = require('jsonwebtoken');

router.post('/', async function (req, res) {
  const admin = {
    name: 'admin',
    pw: 'admin123',
  };

  const user = {
    name: req.headers['user'],
    pw: req.headers['pw'],
  };

  if (admin.name == user.name && admin.pw == user.pw) {
    const token = jwt.sign(user, config.secret, {
      expiresIn: 60 * 5,
    });
    res.send({ auth: true, token });
  } else res.send('Usuario no registrado');
});

module.exports = router;
