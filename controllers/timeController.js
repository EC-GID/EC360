const pool = require('../config/db');
const { sendError, isWeekend } = require('../utils/helpers');

exports.checkIn = async (req, res) => {
  try {
    await pool.execute(
      'INSERT INTO time_entries (user_id, check_in) VALUES (?, UTC_TIMESTAMP())',
      [req.user.id]
    );
    res.json({ message: 'Checked in' });
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to check in');
  }
};

exports.checkOut = async (req, res) => {
  try {
    const [results] = await pool.execute(
      'SELECT id, check_in FROM time_entries WHERE user_id = ? AND check_out IS NULL ORDER BY check_in DESC LIMIT 1',
      [req.user.id]
    );

    if (results.length === 0) return sendError(res, 400, 'No active check-in');

    const { id } = results[0];

    await pool.execute(
      `UPDATE time_entries 
       SET check_out = UTC_TIMESTAMP(), duration_minutes = TIMESTAMPDIFF(MINUTE, check_in, UTC_TIMESTAMP()) 
       WHERE id = ?`,
      [id]
    );

    res.json({ message: 'Checked out successfully' });
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to check out');
  }
};

exports.getMyTimeLogs = async (req, res) => {
  try {
    const [results] = await pool.execute(
      'SELECT * FROM time_entries WHERE user_id = ? ORDER BY check_in DESC LIMIT 50',
      [req.user.id]
    );
    res.json(results);
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to get time logs');
  }
};

exports.getAllTimeLogs = async (req, res) => {
  try {
    const [results] = await pool.execute(
      `SELECT t.*, u.full_name 
       FROM time_entries t 
       JOIN users u ON t.user_id = u.id
       ORDER BY t.check_in DESC LIMIT 100`
    );
    res.json(results);
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to get all time logs');
  }
};
