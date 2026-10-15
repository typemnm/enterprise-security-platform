"use strict";

const { randomBytes } = require("node:crypto");
const { sanitizeHtml } = require("./html-sanitizer");

async function sanitizeReportHtml(html) {
  return sanitizeHtml(html, {
    allowedTags: ["h1", "h2", "h3", "h4", "h5", "h6", "p", "blockquote", "pre", "code", "ul", "ol", "li", "strong", "em", "del", "hr", "br", "table", "thead", "tbody", "tr", "th", "td", "a"],
    allowedAttributes: { a: ["href", "title", "rel"], th: ["colspan", "rowspan"], td: ["colspan", "rowspan"], code: ["class"] },
    allowedClasses: { code: ["language-*"] }, allowedSchemes: ["https", "http", "mailto"],
    allowProtocolRelative: false, disallowedTagsMode: "discard",
    transformTags: { a: (tagName, attributes) => ({ tagName, attribs: { ...attributes, rel: "noopener noreferrer" } }) },
  });
}

function securityHeaders(req, res, next) {
  const nonce = randomBytes(18).toString("base64");
  res.set("Cache-Control", "no-store");
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "no-referrer");
  res.set("X-Frame-Options", "DENY");
  res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.set("Content-Security-Policy", `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'`);
  const send = res.send.bind(res);
  res.send = body => {
    if (typeof body === "string" && body.includes("<!DOCTYPE html>")) {
      const csrf = typeof req.auth?.csrfToken === "string" && /^[A-Za-z0-9_-]{43}$/.test(req.auth.csrfToken) ? req.auth.csrfToken : "";
      body = body.replace("<head>", `<head><meta name="csrf-token" content="${csrf}">`)
        .replace(/<script>/g, `<script nonce="${nonce}">`);
    }
    return send(body);
  };
  next();
}

module.exports = { sanitizeReportHtml, securityHeaders };
