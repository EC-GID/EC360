const pool = require('../config/db');
const { sendError } = require('../utils/helpers');

exports.getDepartments = async (req, res) => {
  try {
    const [results] = await pool.execute('SELECT * FROM departments');
    res.json(results);
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to fetch departments');
  }
};

exports.createDepartment = async (req, res) => {
  const { name, description } = req.body;
  if (!name) return sendError(res, 400, 'Department name is required');

  try {
    const [result] = await pool.execute(
      'INSERT INTO departments (name, description) VALUES (?, ?)',
      [name, description || null]
    );
    res.json({ message: 'Department created', id: result.insertId });
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to create department');
  }
};

exports.deleteDepartment = async (req, res) => {
  try {
    await pool.execute('DELETE FROM departments WHERE id = ?', [req.params.id]);
    res.json({ message: 'Department deleted' });
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to delete department');
  }
};
