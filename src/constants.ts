export const PORT = Number(process.env.DNS_PORT ?? 5353);
export const HOST = process.env.DNS_HOST ?? "0.0.0.0";
export const DB_PATH = process.env.DNS_DB_PATH ?? "./data/dns.sqlite";
export const CACHE_TTL_SECONDS = Number(process.env.DNS_CACHE_TTL_SECONDS ?? 5);
export const HEALTH_CHECK_INTERVAL_SECONDS = Number(process.env.DNS_HEALTH_CHECK_INTERVAL_SECONDS ?? 10);
export const HEALTH_CHECK_TIMEOUT_MS = Number(process.env.DNS_HEALTH_CHECK_TIMEOUT_MS ?? 3000);
export const DNS_RATE_LIMIT_QPS = Number(process.env.DNS_RATE_LIMIT_QPS ?? 200);
export const DNS_RATE_LIMIT_BURST = Number(process.env.DNS_RATE_LIMIT_BURST ?? 400);
export const DNS_RATE_LIMIT_BLOCK_SECONDS = Number(process.env.DNS_RATE_LIMIT_BLOCK_SECONDS ?? 10);

export const QTYPE = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  CAA: 257,
  ANY: 255,
} as const;

export const QCLASS = {
  IN: 1,
} as const;

export const RCODE = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
} as const;
