"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const express = require("express");
const { createRequestErrorHandler } = require("../request-errors");

test("all malformed JSON and size errors have bounded responses and never log raw body or stack in development", async t => {
  const logs = [];
  const app = express();
  app.set("env", "development");
  app.use(express.json({ limit: "1kb" }));
  const paths = ["/api/decision", "/api/reject", "/api/rollback-ip", "/api/block-ip", "/auth/logout", "/unknown-route"];
  let writes = 0;
  for (const path of paths) app.post(path, (req, res) => { writes++; res.json({ ok: true }); });
  app.use(createRequestErrorHandler({ logger: { error: (...args) => logs.push(args) } }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise(resolve => server.once("listening", resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = "http://127.0.0.1:" + server.address().port;
  for (const path of paths) {
    for (const [body, status, code] of [["xoxb-private-callback-token", 400, "invalid_json"],
                                      [JSON.stringify({ task_token: "private".repeat(1000) }), 413, "payload_too_large"]]) {
      const result = await fetch(base + path, { method: "POST", headers: { "Content-Type": "application/json" }, body });
      assert.equal(result.status, status);
      const text = await result.text();
      assert.deepEqual(JSON.parse(text), { ok: false, code });
      assert.doesNotMatch(text, /private|xoxb|SyntaxError|stack|task_token|node_modules/);
    }
  }
  assert.equal(writes, 0);
  assert.deepEqual(logs, []);
});

test("unexpected errors log a static code and never a message, name, URL, header or body", () => {
  const logs = [];
  const handler = createRequestErrorHandler({ logger: { error: (...args) => logs.push(args) } });
  const error = new Error("Bearer private-token");
  error.body = "task_token=private-callback";
  error.stack = "xoxb-private-stack";
  error.name = "private-error-name";
  const req = { url: "/auth/callback?code=private-code", headers: { authorization: "private-auth" } };
  const res = { statusCode: 0, status(value) { this.statusCode = value; return this; }, json(body) { this.body = body; } };
  handler(error, req, res, () => { throw new Error("Must not invoke default error handler"); });
  assert.equal(res.statusCode, 500);
  assert.deepEqual(res.body, { ok: false, code: "internal_error" });
  assert.deepEqual(logs, [[JSON.stringify({ event: "DASHBOARD_REQUEST_ERROR", code: "internal_error" })]]);
});

test("already-started responses close without handing a sensitive error to Express", () => {
  let destroyed = false;
  const handler = createRequestErrorHandler({ logger: { error() {} } });
  handler({ type: "entity.parse.failed", message: "private-body" }, {},
    { headersSent: true, destroy() { destroyed = true; } }, () => { throw new Error("Default logger must not receive errors"); });
  assert.equal(destroyed, true);
});
