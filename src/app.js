const express = require('express');
require('dotenv').config();
const rateLimit = require('express-rate-limit');
const authRoutes = require('./routes/authRoutes');

const app = express();

app.use(express.json());

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: 'Too many requests, please try again later' }
});

app.use(globalLimiter);
app.use('/auth', authRoutes);

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

module.exports = app;