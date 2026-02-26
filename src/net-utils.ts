import { isIP } from "node:net";

function parseIpv4(ip: string): number | null {
  const parts = ip.split(".").map((v) => Number(v));
  if (parts.length !== 4 || parts.some((v) => !Number.isInteger(v) || v < 0 || v > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function parseIpv6(ip: string): Uint8Array | null {
  const [left, right] = ip.split("::");
  const leftParts = left ? left.split(":").filter(Boolean) : [];
  const rightParts = right ? right.split(":").filter(Boolean) : [];
  const fill = 8 - (leftParts.length + rightParts.length);
  if (fill < 0) return null;
  const parts = [...leftParts, ...Array.from({ length: fill }, () => "0"), ...rightParts].map((part) =>
    Number.parseInt(part || "0", 16),
  );
  if (parts.length !== 8 || parts.some((v) => Number.isNaN(v) || v < 0 || v > 0xffff)) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (parts[i]! >> 8) & 0xff;
    out[i * 2 + 1] = parts[i]! & 0xff;
  }
  return out;
}

export function isValidCidr(cidr: string): boolean {
  const trimmed = cidr.trim();
  if (!trimmed) return false;
  const [base, prefixRaw] = trimmed.split("/");
  if (!base || !prefixRaw) return false;
  const version = isIP(base);
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix) || prefix < 0) return false;
  if (version === 4) return prefix <= 32;
  if (version === 6) return prefix <= 128;
  return false;
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const [base, prefixRaw] = cidr.trim().split("/");
  if (!base || !prefixRaw) return false;
  const ipVersion = isIP(ip);
  const baseVersion = isIP(base);
  if (ipVersion === 0 || ipVersion !== baseVersion) return false;
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix)) return false;

  if (ipVersion === 4) {
    const ipNum = parseIpv4(ip);
    const baseNum = parseIpv4(base);
    if (ipNum === null || baseNum === null) return false;
    const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0);
    return (ipNum & mask) === (baseNum & mask);
  }

  const ipBytes = parseIpv6(ip);
  const baseBytes = parseIpv6(base);
  if (!ipBytes || !baseBytes) return false;
  const fullBytes = Math.floor(prefix / 8);
  const remBits = prefix % 8;

  for (let i = 0; i < fullBytes; i++) {
    if (ipBytes[i] !== baseBytes[i]) return false;
  }
  if (remBits === 0) return true;
  const mask = (0xff << (8 - remBits)) & 0xff;
  return (ipBytes[fullBytes]! & mask) === (baseBytes[fullBytes]! & mask);
}

export function parseCidrList(input: string): string[] {
  return input
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function ipMatchesAnyCidr(ip: string, cidrs: string): boolean {
  const list = parseCidrList(cidrs);
  if (list.length === 0) return false;
  return list.some((cidr) => ipInCidr(ip, cidr));
}
