"use strict";

// Lambda disables synchronous require(ESM) by default, including Node.js 24.
// Load the ESM-only parser lazily through the supported CommonJS import() API.
let parser;
async function renderMarkdown(markdown) {
  if (!parser) parser = import("marked");
  const { marked } = await parser;
  return marked.parse(markdown);
}

module.exports = { renderMarkdown };
