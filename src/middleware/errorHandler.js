const { buildError } = require('../utils/response');

function notFoundHandler(req, res) {
  return res.status(404).json(buildError('Resource not found', 404));
}

function errorHandler(err, req, res, next) {
  if (res.headersSent) {
    return next(err);
  }

  const status = err.statusCode || err.status || 500;
  const message = status === 500 ? 'Internal server error' : (err.message || 'Request failed');

  return res.status(status).json(buildError(message, status, process.env.NODE_ENV === 'development' ? { stack: err.stack } : null));
}

module.exports = { notFoundHandler, errorHandler };
