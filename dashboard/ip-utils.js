"use strict";
const ipaddr = require("ipaddr.js");
const { isIP } = require("node:net");
function parseIp(value) {
  if (typeof value !== "string" || value.includes("%") || !isIP(value)) return null;
  const address = ipaddr.parse(value);
  const family = address.kind() === "ipv4" ? 4 : 6;
  return { address, family, ip: family === 4 ? address.toString() : address.toRFC5952String(), prefix: family === 4 ? 32 : 128 };
}
function parseNetwork(value) {
  if (typeof value !== "string") return null;
  const slash = value.lastIndexOf("/");
  const parsed = parseIp(value.slice(0, slash));
  const suffix = value.slice(slash + 1);
  const prefix = Number(suffix);
  if (slash < 1 || !parsed || !/^\d+$/.test(suffix) || String(prefix) !== suffix || prefix < 0 || prefix > parsed.prefix) return null;
  const bytes = parsed.address.toByteArray();
  for (let index = 0; index < bytes.length; index++) {
    const bits = Math.max(0, Math.min(8, prefix - index * 8));
    const mask = bits === 0 ? 0 : (0xff << (8 - bits)) & 0xff;
    if ((bytes[index] & mask) !== bytes[index]) return null;
  }
  return { ...parsed, original: value, prefix, cidr: `${parsed.ip}/${prefix}` };
}
function contains(network, ip) {
  return network && ip && network.family === ip.family && ip.address.match(network.address, network.prefix);
}
function exactHost(network, ip) { return contains(network, ip) && network.prefix === ip.prefix; }
module.exports = { parseIp, parseNetwork, contains, exactHost };
