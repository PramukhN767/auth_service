const express = require('express');
const router = express.Router();
const authenticate = require('../middleware/authenticate');
const { register, login, refresh, logout, logoutAll } = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);
router.post('/refresh', refresh);
router.post('/logout', logout);
router.post('/logout-all', logoutAll);
router.get('/me', authenticate, (req, res) => {
  res.status(200).json({ message: 'Protected route works', user: req.user });
});

module.exports = router;