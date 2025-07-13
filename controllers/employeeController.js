const pool = require('../config/db');
const { sendError } = require('../utils/helpers');

exports.getEmployees = async (req, res) => {
  try {
    const [results] = await pool.execute(
      `SELECT e.id, e.full_name, e.email, e.position, e.date_hired, d.name AS department 
       FROM employees e 
       LEFT JOIN departments d ON e.department_id = d.id`
    );
    res.json(results);
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to fetch employees');
  }
};

exports.createEmployee = async (req, res) => {
  const { full_name, email, position, department_id, date_hired } = req.body;
  if (!full_name || !email) return sendError(res, 400, 'Missing required employee fields');

  try {
    const [result] = await pool.execute(
      'INSERT INTO employees (full_name, email, position, department_id, date_hired) VALUES (?, ?, ?, ?, ?)',
      [full_name, email, position || null, department_id || null, date_hired || null]
    );
    res.json({ message: 'Employee created', id: result.insertId });
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to create employee');
  }
};

exports.updateEmployee = async (req, res) => {
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
    console.error(err);
    sendError(res, 500, 'Failed to update employee');
  }
};

exports.deleteEmployee = async (req, res) => {
  try {
    await pool.execute('DELETE FROM employees WHERE id = ?', [req.params.id]);
    res.json({ message: 'Employee deleted' });
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'Failed to delete employee');
  }
};
