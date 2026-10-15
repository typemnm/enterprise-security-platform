"use strict";

const Module = require("node:module");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");

const EXPECTED = Object.freeze({
  sanitizerVersion: "2.18.0",
  sanitizerSha256: "cabd89cee5d4a3844f4a64b40886da3455bba940e5ed63a218b4891e9275c85d",
  parserVersion: "12.0.0",
  parserSha256: "a87b86d915effe39edf97a54eed19b2d7d86b9d48fca2fd2d345e18307661429",
});

function createSanitizerLoader({ readFile = readFileSync, resolve = require.resolve, importParser = () => import("htmlparser2") } = {}) {
  let sanitizer;
  return async function loadSanitizer() {
    if (!sanitizer) sanitizer = (async () => {
    // sanitize-html 2.18 contains the current security fixes but its CJS
    // entrypoint synchronously requires ESM-only htmlparser2 12. Lambda disables
    // require(ESM). Preload that exact dependency via import(), then evaluate
    // the unchanged, lockfile-pinned CJS package with a module-local resolver.
    const filename = resolve("sanitize-html");
    const parserFilename = resolve("htmlparser2");
    const source = readFile(filename, "utf8");
    const parserSource = readFile(parserFilename, "utf8");
    const sanitizerPackage = JSON.parse(readFile(path.join(path.dirname(filename), "package.json"), "utf8"));
    const parserPackage = JSON.parse(readFile(path.join(path.dirname(parserFilename), "..", "package.json"), "utf8"));
    const sha = value => createHash("sha256").update(value).digest("hex");
    if (sanitizerPackage.version !== EXPECTED.sanitizerVersion || parserPackage.version !== EXPECTED.parserVersion ||
        sha(source) !== EXPECTED.sanitizerSha256 || sha(parserSource) !== EXPECTED.parserSha256) {
      throw new Error("SANITIZER_DEPENDENCY_REVIEW_REQUIRED");
    }
    // Check identities before evaluating either pinned dependency. Upgrades
    // require reviewing this narrow adapter and regenerating the exact hashes.
    const htmlparser = await importParser();
    const dependencyRequire = Module.createRequire(filename);
    const isolated = new Module(filename, module);
    isolated.filename = filename;
    isolated.require = name => name === "htmlparser2" ? htmlparser : dependencyRequire(name);
    isolated._compile(source, filename);
    return isolated.exports;
    })();
    return sanitizer;
  };
}

const loadSanitizer = createSanitizerLoader();
async function sanitizeHtml(html, options) {
  return (await loadSanitizer())(html, options);
}

module.exports = { sanitizeHtml, createSanitizerLoader };
