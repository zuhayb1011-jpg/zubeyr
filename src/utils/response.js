function buildSuccess(data, metadata = {}) {
  return {
    success: true,
    data,
    ...metadata,
  };
}

function buildError(message, status = 500, details = null) {
  return {
    success: false,
    message,
    status,
    ...(details ? { details } : {}),
  };
}

module.exports = { buildSuccess, buildError };
