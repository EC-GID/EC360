const express = require('express');
const adminController = require('../controllers/adminController');
const { authenticateToken, requireAdmin } = require('../middlewares/auth');

const router = express.Router();

router.get('/pending-users', authenticateToken, requireAdmin, adminController.getPendingUsers);
router.patch('/approve-user/:id', authenticateToken, requireAdmin, adminController.approveUser);
router.delete('/reject-user/:id', authenticateToken, requireAdmin, adminController.rejectUser);

module.exports = router;
