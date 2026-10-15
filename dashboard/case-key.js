"use strict";
const PREFIXED = /^([a-z][a-z0-9-]{2,47})\/(inv-[0-9a-f]{32})\.md$/;
const FLAT = /^(inv-[0-9a-f]{32})\.md$/;
const SERVICE = /^[a-z][a-z0-9-]{2,47}$/;
function parseCaseKey(key, defaultServiceId = process.env.DEFAULT_SERVICE_ID) {
  if (typeof key !== "string") return null;
  const prefixed = PREFIXED.exec(key);
  if (prefixed) return { serviceId: prefixed[1], caseId: prefixed[2], key };
  const legacy = FLAT.exec(key);
  if (legacy && SERVICE.test(defaultServiceId || "")) return { serviceId: defaultServiceId, caseId: legacy[1], key, legacy: true };
  return null;
}
module.exports = { parseCaseKey };
