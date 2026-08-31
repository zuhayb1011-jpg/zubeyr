const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'aether-dev-secret';

function createToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function generateRandomToken(prefix = 'token') {
  return `${prefix}_${crypto.randomBytes(24).toString('hex')}`;
}

module.exports = { createToken, verifyToken, generateRandomToken };
