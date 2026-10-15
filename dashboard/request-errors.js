"use strict";

function createRequestErrorHandler({ logger = console } = {}) {
  return function requestErrors(error, req, res, next) {
    const type = error?.type;
    const code = type === "entity.too.large" ? "payload_too_large" : type === "entity.parse.failed" ? "invalid_json" : "internal_error";
    const status = code === "payload_too_large" ? 413 : code === "invalid_json" ? 400 : 500;
    // body-parser errors include the raw body and a JSON preview in message/
    // stack. Never pass those errors to Express's default renderer or logger.
    if (code === "internal_error") logger.error(JSON.stringify({ event: "DASHBOARD_REQUEST_ERROR", code }));
    if (res.headersSent) { res.destroy(); return; }
    return res.status(status).json({ ok: false, code });
  };
}

module.exports = { createRequestErrorHandler };
