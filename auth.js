const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const winston = require('winston');

const app = express();

const logger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.Console({ format: winston.format.simple() }),
    new winston.transports.File({ filename: 'combined.log' })
  ],
});

const REQUIRED_ENVS = ['DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME', 'MAIL_HOST', 'MAIL_PORT', 'MAIL_USER', 'MAIL_PASS', 'JWT_SECRET'];
for (const key of REQUIRED_ENVS) {
  if (!process.env[key]) {
    logger.error(`❌ Missing environment variable: ${key}`);
    process.exit(1);
  }
}

const allowedOrigins = new Set([process.env.ALLOWED_ORIGIN]);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  }
}));

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use(express.json());

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};
const pool = mysql.createPool(dbConfig);

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: Number(process.env.MAIL_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

const JWT_SECRET = process.env.JWT_SECRET;

function sendError(res, status, message) {
  logger.error(message);
  res.status(status).json({ error: message });
}

async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return sendError(res, 401, 'Authorization header missing');

    const token = authHeader.split(' ')[1];
    if (!token) return sendError(res, 401, 'Token missing');

    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    sendError(res, 403, 'Invalid or expired token');
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return sendError(res, 403, 'Access denied');
  next();
}

function gracefulShutdown(server) {
  process.on('SIGTERM', () => {
    logger.info("SIGTERM received. Shutting down...");
    server.close(() => {
      logger.info("Server closed.");
    });
  });
}

app.post('/register', async (req, res) => {
  const { full_name, email, password, role } = req.body;
  if (!full_name || !email || !password) return sendError(res, 400, 'Missing required fields');

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const isSuperAdmin = role === 'admin' && email === 'ecloudsm@gmail.com';
    const token = isSuperAdmin ? null : crypto.randomBytes(32).toString('hex');

    const [result] = await pool.execute(
      `INSERT INTO users (full_name, email, password, role, verification_token, is_approved, email_verified)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [full_name, email, hashedPassword, role || 'worker', token, isSuperAdmin ? 1 : 0, isSuperAdmin ? 1 : 0]
    );

    if (isSuperAdmin) {
      return res.json({ message: '✅ Super admin registered, approved, and verified automatically.' });
    }

    const link = `https://ec360.netlify.app/verify-email?token=${token}`;
    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: 'Verify Your Email',
      html: `<p>Hello ${full_name},</p><p>Please verify your email by clicking the link below:</p><a href="${link}">Verify Email</a>`,
    });

    res.json({ message: '✅ Registered. Please check your email to verify your account.' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return sendError(res, 409, 'Email already registered');
    }
    logger.error(err);
    sendError(res, 500, 'Registration failed');
  }
});

app.get('/verify-email', async (req, res) => {
  const token = req.query.token;
  if (!token) return sendError(res, 400, 'Verification token missing');

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE verification_token = ?', [token]);
    if (rows.length === 0) return sendError(res, 400, 'Invalid or expired verification link');

    const user = rows[0];
    if (user.email_verified) return sendError(res, 400, 'Email already verified');

    await pool.execute(
      'UPDATE users SET email_verified = 1, verification_token = NULL WHERE id = ?',
      [user.id]
    );

    res.json({ message: '✅ Email verified successfully. You can now log in.' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Verification failed');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return sendError(res, 400, 'Missing email or password');

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return sendError(res, 400, 'User not found');

    const user = rows[0];
    if (!user.email_verified) return sendError(res, 403, 'Verify email first');
    if (!user.is_approved) return sendError(res, 403, 'Awaiting admin approval');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return sendError(res, 400, 'Invalid password');

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '8h' });

    res.json({
      token,
      user: { id: user.id, full_name: user.full_name, email: user.email, role: user.role },
    });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Login failed');
  }
});

app.post('/resend-verification', async (req, res) => {
  const { email } = req.body;
  if (!email) return sendError(res, 400, 'Email missing');

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return sendError(res, 404, 'User not found');

    const user = rows[0];
    if (user.email_verified) return sendError(res, 400, 'Email already verified');

    const token = crypto.randomBytes(32).toString('hex');
    await pool.execute('UPDATE users SET verification_token = ? WHERE id = ?', [token, user.id]);

    const link = `https://ec360.netlify.app/verify-email?token=${token}`;
    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: 'Resend Email Verification',
      html: `<p>Hello ${user.full_name},</p><a href="${link}">Verify Email</a>`,
    });

    res.json({ message: 'Verification email resent' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to resend verification email');
  }
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return sendError(res, 400, 'Email missing');

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return sendError(res, 404, 'User not found');

    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 15 * 60 * 1000);

    await pool.execute(
      'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?',
      [token, expiry, email]
    );

    const link = `https://ec360.netlify.app/reset-password?token=${token}`;
    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: 'Reset Your Password',
      html: `<p>Click the link to reset your password:</p><a href="${link}">Reset Password</a>`,
    });

    res.json({ message: 'Password reset link sent to email' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to send password reset link');
  }
});

app.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return sendError(res, 400, 'Missing token or password');

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()',
      [token]
    );

    if (rows.length === 0) return sendError(res, 400, 'Invalid or expired token');

    await pool.execute(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
      [hashedPassword, rows[0].id]
    );

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to reset password');
  }
});

app.get('/admin/pending-users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [results] = await pool.execute(
      'SELECT id, full_name, email, role FROM users WHERE is_approved = 0 AND email_verified = 1'
    );
    res.json(results);
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to fetch pending users');
  }
});

app.patch('/admin/approve-user/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [id]);
    res.json({ message: 'User approved' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to approve user');
  }
});

app.delete('/admin/reject-user/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (id === '1') return sendError(res, 403, 'Cannot delete super admin');

  try {
    const [result] = await pool.execute(
      'DELETE FROM users WHERE id = ? AND is_approved = 0',
      [id]
    );
    if (result.affectedRows === 0) return sendError(res, 404, 'User not found or already approved');
    res.json({ message: 'User rejected & deleted' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to reject user');
  }
});

app.get('/', (req, res) => {
  res.send('✅ API is running');
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  logger.info(`🚀 Server running on port ${PORT}`);
});

gracefulShutdown(server);
