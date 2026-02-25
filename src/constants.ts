export const PORT = Number(process.env.DNS_PORT ?? 5353);
export const HOST = process.env.DNS_HOST ?? "0.0.0.0";
export const DB_PATH = process.env.DNS_DB_PATH ?? "./data/dns.sqlite";
export const CACHE_TTL_SECONDS = Number(process.env.DNS_CACHE_TTL_SECONDS ?? 5);

export const QTYPE = {
  A: 1,
  CNAME: 5,
  AAAA: 28,
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
