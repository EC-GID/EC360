const express = require('express');
const { createPool } = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');

const app = express();
const { verify, sign } = jwt;

app.use(helmet());
app.use(compression());
app.use(express.json());

const allowedOrigins = process.env.NODE_ENV === 'production' ? ['https://ec360.netlify.app'] : ['http://localhost:4200'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  }
}));

['DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME', 'MAIL_USER', 'MAIL_PASS', 'JWT_SECRET'].forEach(key => {
  if (!process.env[key]) {
    console.warn(`❌ Missing env: ${key}`);
  }
});

const pool = createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

const JWT_SECRET = process.env.JWT_SECRET;

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  next();
}

app.post('/register', async (req, res) => {
  const { full_name, email, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const isSuperAdmin = role === 'admin' && email === 'ecloudsm@gmail.com';
    const token = isSuperAdmin ? null : crypto.randomBytes(32).toString('hex');

    pool.query(
      'INSERT INTO users (full_name, email, password, role, verification_token, is_approved, email_verified) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        full_name,
        email,
        hashedPassword,
        role || 'worker',
        token,
        isSuperAdmin ? 1 : 0,
        isSuperAdmin ? 1 : 0
      ],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });

        if (isSuperAdmin) {
          return res.json({ message: '✅ Super admin registered, approved, and verified automatically.' });
        }

        const link = `${baseUrl}/verify-email?token=${token}`;
        const mailOptions = {
          from: process.env.MAIL_USER,
          to: email,
          subject: 'Verify Your Email',
          html: `<p>Hello ${full_name},</p><p>Please verify your email by clicking the link below:</p><a href="${link}">Verify Email</a>`
        };

        transporter.sendMail(mailOptions, (error) => {
          if (error) return res.status(500).json({ error: 'Failed to send verification email' });
          res.json({ message: '✅ Registered. Please check your email to verify your account.' });
        });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Registration error' });
  }
});

app.get('/verify-email', (req, res) => {
  const token = req.query.token;

  pool.query('SELECT * FROM users WHERE verification_token = ?', [token], (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired verification link' });
    }

    const user = results[0];

    if (user.email_verified) {
      return res.status(400).json({ error: 'Email already verified' });
    }

    pool.query(
      'UPDATE users SET email_verified = 1, verification_token = NULL WHERE id = ?',
      [user.id],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: '✅ Email verified successfully. You can now log in.' });
      }
    );
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  pool.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(400).json({ error: 'User not found' });

    const user = results[0];
    if (!user.email_verified) return res.status(403).json({ error: 'Verify email first' });
    if (!user.is_approved) return res.status(403).json({ error: 'Awaiting admin approval' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid password' });

    const token = sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: user.id, full_name: user.full_name, email: user.email, role: user.role } });
  });
});

app.post('/resend-verification', (req, res) => {
  const { email } = req.body;
  pool.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = results[0];
    if (user.email_verified) return res.status(400).json({ error: 'Email already verified' });

    const token = crypto.randomBytes(32).toString('hex');
    pool.query('UPDATE users SET verification_token = ? WHERE id = ?', [token, user.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });

      const link = `${baseUrl}/verify-email?token=${token}`;
      const mailOptions = {
        from: process.env.MAIL_USER,
        to: email,
        subject: 'Resend Email Verification',
        html: `<p>Hello ${user.full_name},</p><a href="${link}">Verify Email</a>`
      };

      transporter.sendMail(mailOptions, (error) => {
        if (error) return res.status(500).json({ error: 'Failed to send email' });
        res.json({ message: 'Verification email resent' });
      });
    });
  });
});

app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(32).toString('hex');
  const expiry = new Date(Date.now() + 15 * 60 * 1000);

  pool.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: 'User not found' });

    pool.query('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?', [token, expiry, email], (err2) => {
      if (err2) return res.status(500).json({ error: 'Failed to set token' });

      const link = `${baseUrl}/reset-password?token=${token}`;
      const mailOptions = {
        from: process.env.MAIL_USER,
        to: email,
        subject: 'Reset Your Password',
        html: `<p>Click the link to reset your password:</p><a href="${link}">Reset Password</a>`
      };

      transporter.sendMail(mailOptions, (err3) => {
        if (err3) return res.status(500).json({ error: 'Failed to send email' });
        res.json({ message: 'Password reset link sent to email' });
      });
    });
  });
});

app.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  pool.query('SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()', [token], (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ error: 'Invalid or expired token' });

    pool.query(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
      [hashedPassword, results[0].id],
      (err2) => {
        if (err2) return res.status(500).json({ error: 'Failed to reset password' });
        res.json({ message: 'Password reset successful' });
      }
    );
  });
});

app.listen(process.env.PORT || 3000, () => console.log(`Server running on port ${process.env.PORT || 3000}`));
