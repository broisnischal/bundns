import type { Database } from "bun:sqlite";
import { CACHE_TTL_SECONDS } from "./constants";
import { normalizeDomain, normalizeFqdn, openDatabase } from "./db";
import type { DnsRecord } from "./types";

type CacheEntry = {
  expiresAt: number;
  records: DnsRecord[];
};

export type LookupResult = {
  zoneName: string | null;
  nameExists: boolean;
  records: DnsRecord[];
  authorityRecords: DnsRecord[];
};

export class DnsRepository {
  private readonly db: Database;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly cacheTtlMs: number;
  private readonly getByNameStmt;
  private readonly zonesBySuffixStmt;
  private readonly authorityByZoneStmt;

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

    this.zonesBySuffixStmt = this.db.query<{ name: string }, [string]>(`
      SELECT name
      FROM domains
      WHERE ?1 = name OR ?1 LIKE '%.' || name
      ORDER BY LENGTH(name) DESC
    `);
    this.authorityByZoneStmt = this.db.query<DnsRecord, [string]>(`
      SELECT type, ttl, value
      FROM records
      WHERE fqdn = ?1
        AND type IN ('SOA', 'NS')
      ORDER BY
        CASE type
          WHEN 'SOA' THEN 0
          WHEN 'NS' THEN 1
          ELSE 2
        END,
        id ASC
    `);
  }

  lookup(name: string): LookupResult {
    const fqdn = normalizeFqdn(name);
    const bare = normalizeDomain(fqdn);
    const now = Date.now();
    const cached = this.cache.get(fqdn);
    if (cached && now < cached.expiresAt) {
      const zoneName = this.resolveZoneName(bare);
      return {
        zoneName,
        nameExists: cached.records.length > 0,
        records: cached.records,
        authorityRecords: this.getAuthorityRecords(zoneName),
      };
    }

    const records = this.getByNameStmt.all(fqdn);
    if (this.cacheTtlMs > 0) {
      this.cache.set(fqdn, {
        expiresAt: now + this.cacheTtlMs,
        records,
      });
    }

    const zoneName = this.resolveZoneName(bare);
    return {
      zoneName,
      nameExists: records.length > 0,
      records,
      authorityRecords: this.getAuthorityRecords(zoneName),
    };
  }

  private resolveZoneName(nameWithoutDot: string): string | null {
    const row = this.zonesBySuffixStmt.get(nameWithoutDot);
    if (!row) return null;
    return normalizeFqdn(row.name);
  }

  private getAuthorityRecords(zoneName: string | null): DnsRecord[] {
    if (!zoneName) return [];
    return this.authorityByZoneStmt.all(zoneName);
  }

  close() {
    this.db.close();
  }
}
