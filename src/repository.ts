import type { Database } from "bun:sqlite";
import { CACHE_TTL_SECONDS } from "./constants";
import { normalizeFqdn, openDatabase } from "./db";
import type { DnsRecord } from "./types";

type CacheEntry = {
  expiresAt: number;
  records: DnsRecord[];
};

export class DnsRepository {
  private readonly db: Database;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly cacheTtlMs: number;
  private readonly getByNameStmt;
  private readonly existsByNameStmt;

  constructor(dbPath: string, cacheTtlSeconds = CACHE_TTL_SECONDS) {
    this.db = openDatabase(dbPath);
    this.cacheTtlMs = Math.max(0, cacheTtlSeconds) * 1000;

    this.getByNameStmt = this.db.query<DnsRecord, [string]>(`
      SELECT type, ttl, value
      FROM records
      WHERE fqdn = ?1
      ORDER BY
        CASE type
          WHEN 'CNAME' THEN 0
          WHEN 'A' THEN 1
          WHEN 'AAAA' THEN 2
          ELSE 3
        END,
        id ASC
    `);

    this.existsByNameStmt = this.db.query<{ found: number }, [string]>(`
      SELECT 1 AS found
      FROM records
      WHERE fqdn = ?1
      LIMIT 1
    `);
  }

  lookup(name: string): { exists: boolean; records: DnsRecord[] } {
    const fqdn = normalizeFqdn(name);
    const now = Date.now();
    const cached = this.cache.get(fqdn);
    if (cached && now < cached.expiresAt) {
      return { exists: cached.records.length > 0, records: cached.records };
    }

    const records = this.getByNameStmt.all(fqdn);
    if (this.cacheTtlMs > 0) {
      this.cache.set(fqdn, {
        expiresAt: now + this.cacheTtlMs,
        records,
      });
    }

    if (records.length > 0) {
      return { exists: true, records };
    }

    const exists = Boolean(this.existsByNameStmt.get(fqdn));
    return { exists, records };
  }

  close() {
    this.db.close();
  }
}
