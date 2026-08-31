const { get } = require('../../db');
const { verifyToken } = require('../utils/auth');
const { buildError } = require('../utils/response');

async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json(buildError('Authentication required', 401));
    }

    const decoded = verifyToken(token);
    const user = await get('SELECT * FROM users WHERE id = ?', [decoded.id]);

    if (!user) {
      return res.status(401).json(buildError('Invalid session', 401));
    }

    req.user = { ...user, password: undefined };
    next();
  } catch (error) {
    return res.status(401).json(buildError('Invalid or expired token', 401));
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json(buildError('Authentication required', 401));
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json(buildError('You are not authorized to access this resource', 403));
    }

    next();
  };
}

module.exports = { requireAuth, requireRole };
