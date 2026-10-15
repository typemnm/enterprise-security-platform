"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { readFileSync } = require("node:fs");
const { createSanitizerLoader } = require("../html-sanitizer");

test("cold-started Lambda supports health, Markdown and ESM JOSE with synchronous ESM require disabled", () => {
  const script = String.raw`
    const assert = require('node:assert/strict');
    const clients = {
      '@aws-sdk/client-s3': 'S3Client', '@aws-sdk/client-dynamodb': 'DynamoDBClient',
      '@aws-sdk/client-lambda': 'LambdaClient', '@aws-sdk/client-wafv2': 'WAFV2Client',
      '@aws-sdk/client-sfn': 'SFNClient'
    };
    for (const [module, name] of Object.entries(clients)) {
      require(module)[name].prototype.send = () => { throw new Error('Health must not call AWS'); };
    }
    const { handler } = require('./lambda');
    const event = {
      version: '2.0', routeKey: 'ANY /{proxy+}', rawPath: '/healthz', rawQueryString: '',
      headers: { host: 'dashboard.example' }, isBase64Encoded: false,
      requestContext: { stage: '$default', http: { method: 'GET', path: '/healthz', sourceIp: '127.0.0.1' } }
    };
    (async () => {
      const result = await handler(event, { awsRequestId: 'offline-cold-start' });
      assert.equal(result.statusCode, 200);
      assert.deepEqual(JSON.parse(result.body), { ok: true });
      const { renderMarkdown } = require('./markdown');
      const { sanitizeReportHtml } = require('./content-security');
      const report = await sanitizeReportHtml(await renderMarkdown('# Report\n\n<script>secret()</script>\n\n**safe summary**'));
      assert.match(report, /<h1>Report<\/h1>/);
      assert.match(report, /<strong>safe summary<\/strong>/);
      assert.doesNotMatch(report, /secret\(\)|<script>/);
      const jose = await import('jose');
      const key = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const token = await new jose.SignJWT({ token_use: 'access' }).setProtectedHeader({ alg: 'RS256' })
        .setSubject('offline-sub').setIssuer('https://idp.example/pool').setIssuedAt().setExpirationTime('1m').sign(key.privateKey);
      assert.equal((await jose.jwtVerify(token, key.publicKey, { issuer: 'https://idp.example/pool' })).payload.sub, 'offline-sub');
      process.stdout.write('lambda strict-runtime health/markdown/jose passed');
    })().catch(error => { process.stderr.write(error.stack); process.exitCode = 1; });
  `;
  const child = spawnSync(process.execPath, ["--no-experimental-require-module", "-e", script], {
    cwd: path.join(__dirname, ".."), encoding: "utf8", timeout: 30000,
    env: { ...process.env, AWS_EC2_METADATA_DISABLED: "true" },
  });
  assert.equal(child.status, 0, child.stderr);
  assert.match(child.stdout, /lambda strict-runtime health\/markdown\/jose passed/);
});

test("sanitizer dependency upgrades or modified entrypoints fail closed before evaluating package code", async () => {
  for (const variant of ["sanitizer-version", "parser-version", "sanitizer-source", "parser-source"]) {
    let imports = 0;
    const load = createSanitizerLoader({
      readFile(filename, encoding) {
        const original = readFileSync(filename, encoding);
        if (filename.endsWith("package.json") &&
            (variant === "sanitizer-version" && filename.includes("sanitize-html") ||
             variant === "parser-version" && filename.includes("htmlparser2"))) {
          const metadata = JSON.parse(original);
          return JSON.stringify({ ...metadata, version: "99.0.0" });
        }
        if (!filename.endsWith("package.json") &&
            (variant === "sanitizer-source" && filename.includes("sanitize-html") ||
             variant === "parser-source" && filename.includes("htmlparser2"))) return original + "\n// changed dependency";
        return original;
      },
      importParser: async () => { imports++; throw new Error("Changed dependency must not execute"); },
    });
    await assert.rejects(load, /SANITIZER_DEPENDENCY_REVIEW_REQUIRED/);
    assert.equal(imports, 0);
  }
});
