const pool = require('../config/db');
const { sendError } = require('../utils/helpers');

exports.getPendingUsers = async (req, res) => {
  try {
    const [results] = await pool.execute(
      'SELECT id, full_name, email, role FROM users WHERE is_approved = 0 AND email_verified = 1'
    );
    res.json(results);
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to fetch pending users');
  }
};

exports.approveUser = async (req, res) => {
  const { id } = req.params;
  try {
    await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [id]);
    res.json({ message: 'User approved' });
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to approve user');
  }
};

exports.rejectUser = async (req, res) => {
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
    console.error(err);
    sendError(res, 500, 'Failed to reject user');
  }
};
