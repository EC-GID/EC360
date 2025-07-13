function sendError(res, status, message) {
  res.status(status).json({ error: message });
}

function isWeekend(date) {
  const day = date.getUTCDay();
  return day === 0 || day === 6;
}

module.exports = { sendError, isWeekend };
