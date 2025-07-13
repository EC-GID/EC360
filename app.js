require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const departmentRoutes = require('./routes/departmentRoutes');
const employeeRoutes = require('./routes/employeeRoutes');
const timeRoutes = require('./routes/timeRoutes');

const { errorHandler } = require('./middlewares/errorHandler');

const app = express();

const allowedOrigins = new Set(['http://localhost:4200', 'http://127.0.0.1:4200']);
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

app.use(authRoutes);
app.use('/admin', adminRoutes);
app.use('/departments', departmentRoutes);
app.use('/employees', employeeRoutes);
app.use('/time', timeRoutes);

app.get('/', (req, res) => res.send('✅ API is running'));

app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
