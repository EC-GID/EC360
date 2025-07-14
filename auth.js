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

app.use(cors({
  origin: 'https://ec360.netlify.app',
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));


const logger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.Console({ format: winston.format.simple() }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

const REQUIRED_ENVS = ['DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME', 'DB_PORT', 'JWT_SECRET', 'MAIL_USER', 'MAIL_PASS'];
for (const key of REQUIRED_ENVS) {
  if (!process.env[key]) {
    logger.error(`Missing environment variable: ${key}`);
    process.exit(1);
  }
}

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use(express.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT),
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

const JWT_SECRET = process.env.JWT_SECRET;

function sendError(res, status, message) {
  res.status(status).json({ error: message });
  logger.warn(`Response error ${status}: ${message}`);
}

async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      sendError(res, 401, 'Authorization header missing');
      return;
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
      sendError(res, 401, 'Token missing');
      return;
    }
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch {
    sendError(res, 403, 'Invalid or expired token');
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    sendError(res, 403, 'Access denied');
    return;
  }
  next();
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
      [
        full_name,
        email,
        hashedPassword,
        role || 'worker',
        token,
        isSuperAdmin ? 1 : 0,
        isSuperAdmin ? 1 : 0,
      ]
    );
    if (isSuperAdmin) {
      res.json({ message: 'Super admin registered, approved, and verified.' });
      return;
    }
    const link = `https://ec360.netlify.app/verify-email?token=${token}`;
    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: 'Verify Your Email',
      html: `<p>Hello ${full_name},</p><p>Please verify your email by clicking the link below:</p><a href="${link}">Verify Email</a>`,
    });
    res.json({ message: 'Registered. Please check your email to verify your account.' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return sendError(res, 409, 'Email already registered');
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
    await pool.execute('UPDATE users SET email_verified = 1, verification_token = NULL WHERE id = ?', [user.id]);
    res.json({ message: 'Email verified successfully. You can now log in.' });
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
    await pool.execute('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?', [token, expiry, email]);
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
    const [rows] = await pool.execute('SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()', [token]);
    if (rows.length === 0) return sendError(res, 400, 'Invalid or expired token');
    await pool.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?', [hashedPassword, rows[0].id]);
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to reset password');
  }
});

app.get('/admin/pending-users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [results] = await pool.execute('SELECT id, full_name, email, role FROM users WHERE is_approved = 0 AND email_verified = 1');
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
    const [result] = await pool.execute('DELETE FROM users WHERE id = ? AND is_approved = 0', [id]);
    if (result.affectedRows === 0) return sendError(res, 404, 'User not found or already approved');
    res.json({ message: 'User rejected & deleted' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to reject user');
  }
});

app.get('/departments', async (req, res) => {
  try {
    const [results] = await pool.execute('SELECT * FROM departments');
    res.json(results);
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to fetch departments');
  }
});

app.post('/departments', async (req, res) => {
  const { name, description } = req.body;
  if (!name) return sendError(res, 400, 'Department name is required');
  try {
    const [result] = await pool.execute('INSERT INTO departments (name, description) VALUES (?, ?)', [name, description || null]);
    res.json({ message: 'Department created', id: result.insertId });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to create department');
  }
});

app.delete('/departments/:id', async (req, res) => {
  try {
    await pool.execute('DELETE FROM departments WHERE id = ?', [req.params.id]);
    res.json({ message: 'Department deleted' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to delete department');
  }
});

app.get('/employees', async (req, res) => {
  try {
    const [results] = await pool.execute(
      `SELECT e.id, e.full_name, e.email, e.position, e.date_hired, d.name AS department 
       FROM employees e 
       LEFT JOIN departments d ON e.department_id = d.id`
    );
    res.json(results);
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to fetch employees');
  }
});

app.post('/employees', async (req, res) => {
  const { full_name, email, position, department_id, date_hired } = req.body;
  if (!full_name || !email) return sendError(res, 400, 'Missing required employee fields');
  try {
    const [result] = await pool.execute(
      'INSERT INTO employees (full_name, email, position, department_id, date_hired) VALUES (?, ?, ?, ?, ?)',
      [full_name, email, position || null, department_id || null, date_hired || null]
    );
    res.json({ message: 'Employee created', id: result.insertId });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to create employee');
  }
});

app.put('/employees/:id', async (req, res) => {
  const { full_name, email, position, department_id, date_hired } = req.body;
  const { id } = req.params;
  if (!full_name || !email) return sendError(res, 400, 'Missing required employee fields');
  try {
    await pool.execute(
      'UPDATE employees SET full_name = ?, email = ?, position = ?, department_id = ?, date_hired = ? WHERE id = ?',
      [full_name, email, position || null, department_id || null, date_hired || null, id]
    );
    res.json({ message: 'Employee updated' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to update employee');
  }
});

app.delete('/employees/:id', async (req, res) => {
  try {
    await pool.execute('DELETE FROM employees WHERE id = ?', [req.params.id]);
    res.json({ message: 'Employee deleted' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to delete employee');
  }
});

app.post('/check-in', authenticateToken, async (req, res) => {
  try {
    await pool.execute('INSERT INTO time_entries (user_id, check_in) VALUES (?, UTC_TIMESTAMP())', [req.user.id]);
    res.json({ message: 'Checked in' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to check in');
  }
});

app.post('/check-out', authenticateToken, async (req, res) => {
  try {
    const [results] = await pool.execute(
      'SELECT id FROM time_entries WHERE user_id = ? AND check_out IS NULL ORDER BY check_in DESC LIMIT 1',
      [req.user.id]
    );
    if (results.length === 0) return sendError(res, 400, 'No active check-in');
    const { id } = results[0];
    await pool.execute(
      `UPDATE time_entries SET check_out = UTC_TIMESTAMP(), duration_minutes = TIMESTAMPDIFF(MINUTE, check_in, UTC_TIMESTAMP()) WHERE id = ?`,
      [id]
    );
    res.json({ message: 'Checked out successfully' });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to check out');
  }
});

app.get('/my-time-logs', authenticateToken, async (req, res) => {
  try {
    const [results] = await pool.execute('SELECT check_in, check_out, duration_minutes FROM time_entries WHERE user_id = ? ORDER BY check_in DESC', [req.user.id]);
    res.json(results);
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to fetch time logs');
  }
});

app.get('/admin/time-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [results] = await pool.execute(
      `SELECT t.id, u.full_name, t.check_in, t.check_out, t.duration_minutes 
       FROM time_entries t 
       JOIN users u ON t.user_id = u.id 
       ORDER BY t.check_in DESC`
    );
    res.json(results);
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to fetch admin time logs');
  }
});

app.get('/check-status', authenticateToken, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const [results] = await pool.execute('SELECT check_in, check_out FROM time_entries WHERE user_id = ? AND DATE(check_in) = ?', [req.user.id, today]);
    let checkedIn = false, checkedOut = false;
    if (results.length > 0) {
      checkedIn = true;
      checkedOut = results[0].check_out !== null;
    }
    res.json({ checkedIn, checkedOut });
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to check status');
  }
});

function isWeekend(date) {
  const day = date.getUTCDay();
  return day === 0 || day === 6;
}

app.get('/admin/weekly-payments', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const today = new Date();
    const endDate = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate(), 23, 59, 59));
    const startDate = new Date(endDate);
    startDate.setUTCDate(endDate.getUTCDate() - 6);
    const [rows] = await pool.execute(
      `SELECT u.id AS user_id, u.full_name, SUM(t.duration_minutes) AS total_minutes 
       FROM time_entries t 
       JOIN users u ON t.user_id = u.id 
       WHERE t.check_in BETWEEN ? AND ? 
       GROUP BY u.id, u.full_name`,
      [startDate.toISOString(), endDate.toISOString()]
    );
    const payments = rows.map(row => {
      const totalHours = (row.total_minutes || 0) / 60;
      const payRate = 5;
      return {
        user_id: row.user_id,
        full_name: row.full_name,
        total_hours: totalHours.toFixed(2),
        amount_due: (totalHours * payRate).toFixed(2),
      };
    });
    res.json(payments);
  } catch (err) {
    logger.error(err);
    sendError(res, 500, 'Failed to fetch weekly payments');
  }
});

app.get('/', (req, res) => {
  res.send('API running');
  logger.info('Root accessed');
});

app.use((err, req, res, next) => {
  logger.error(err.message);
  sendError(res, 500, 'Internal Server Error');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server started on port ${PORT}`);
});
