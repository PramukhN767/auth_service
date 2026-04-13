const express = require('express');
const router = express.Router();
const { register, login, refresh, logout, logoutAll } = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);
router.post('/refresh', refresh);
router.post('/logout', logout);
router.post('/logout-all', logoutAll);

module.exports = router;