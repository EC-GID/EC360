const express = require('express');
const timeController = require('../controllers/timeController');
const { authenticateToken, requireAdmin } = require('../middlewares/auth');

const router = express.Router();

router.post('/check-in', authenticateToken, timeController.checkIn);
router.post('/check-out', authenticateToken, timeController.checkOut);
router.get('/my-logs', authenticateToken, timeController.getMyTimeLogs);
router.get('/all-logs', authenticateToken, requireAdmin, timeController.getAllTimeLogs);

module.exports = router;
