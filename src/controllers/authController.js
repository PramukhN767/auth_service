const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const redisClient = require('../config/redis');
const { createUser, findUserByEmail } = require('../models/userModel');
const { saveRefreshToken, findRefreshToken, deleteRefreshToken, deleteAllRefreshTokens } = require('../models/refreshTokenModel');

const register = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({ message: 'Email already in use' });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save user to database
    const user = await createUser(email, hashedPassword);

    res.status(201).json({
      message: 'User registered successfully',
      user
    });

  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Check if user exists
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Sign JWT
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );


  const refreshToken = jwt.sign(
    { userId: user.id },
    process.env.JWT_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN }
  );

  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  await saveRefreshToken(user.id, refreshToken, expiresAt);

  res.status(200).json({
    message: 'Login successful',
    accessToken,
    refreshToken
  });

  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }

    const stored = await findRefreshToken(refreshToken);
    if (!stored) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    if (new Date() > new Date(stored.expires_at)) {
      await deleteRefreshToken(refreshToken);
      return res.status(401).json({ message: 'Refresh token expired' });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

    const accessToken = jwt.sign(
      { userId: decoded.userId },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(200).json({ accessToken });

  } catch (err) {
    console.error('Refresh error:', err.message);
    res.status(401).json({ message: 'Invalid refresh token' });
  }
};

const logout = async (req, res) => {
  try {
    const { refreshToken, accessToken } = req.body;

    if (!refreshToken || !accessToken) {
      return res.status(400).json({ message: 'Refresh token and access token are required' });
    }

    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
    const ttl = decoded.exp - Math.floor(Date.now() / 1000); 

    if (ttl > 0) {
      await redisClient.setEx(`blacklist:${accessToken}`, ttl, 'true');
    }

    await deleteRefreshToken(refreshToken);

    res.status(200).json({ message: 'Logged out successfully' });

  } catch (err) {
    console.error('Logout error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const logoutAll = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }

    await deleteAllRefreshTokens(userId);

    res.status(200).json({ message: 'Logged out from all devices' });

  } catch (err) {
    console.error('Logout all error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
};

module.exports = { register, login, refresh, logout, logoutAll };