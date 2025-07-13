const jwt = require('jsonwebtoken');
const { sendError } = require('../utils/helpers');

const JWT_SECRET = process.env.JWT_SECRET;

async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return sendError(res, 401, 'Authorization header missing');

    const token = authHeader.split(' ')[1];
    if (!token) return sendError(res, 401, 'Token missing');

    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch {
    sendError(res, 403, 'Invalid or expired token');
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return sendError(res, 403, 'Access denied');
  next();
}

module.exports = { authenticateToken, requireAdmin };
