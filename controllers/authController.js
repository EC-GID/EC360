const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const pool = require('../config/db');
const transporter = require('../config/mail');
const { sendError } = require('../utils/helpers');

const JWT_SECRET = process.env.JWT_SECRET;

exports.register = async (req, res) => {
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
    console.error(err);
    sendError(res, 500, 'Registration failed');
  }
};

exports.verifyEmail = async (req, res) => {
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
    console.error(err);
    sendError(res, 500, 'Verification failed');
  }
};

exports.login = async (req, res) => {
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
    console.error(err);
    sendError(res, 500, 'Login failed');
  }
};

exports.resendVerification = async (req, res) => {
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
    console.error(err);
    sendError(res, 500, 'Failed to resend verification email');
  }
};

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) return sendError(res, 400, 'Email missing');

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return sendError(res, 404, 'User not found');

    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 15 * 60 * 1000); // 15 mins

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
    console.error(err);
    sendError(res, 500, 'Failed to send password reset link');
  }
};

exports.resetPassword = async (req, res) => {
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
    console.error(err);
    sendError(res, 500, 'Failed to reset password');
  }
};
