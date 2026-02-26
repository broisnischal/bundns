import type { Database } from "bun:sqlite";
import {
  CACHE_TTL_SECONDS,
  HEALTH_CHECK_INTERVAL_SECONDS,
  HEALTH_CHECK_TIMEOUT_MS,
  QTYPE,
} from "./constants";
import { ipMatchesAnyCidr } from "./net-utils";
import { normalizeDomain, normalizeFqdn, openDatabase } from "./db";
import type { DnsRecord } from "./types";

type CacheEntry = {
  expiresAt: number;
  records: StoredRecord[];
};

type StoredRecord = DnsRecord & {
  id: number;
  weight: number;
  geo_cidrs: string;
  enabled: number;
  healthcheck_url: string | null;
  healthy: number;
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
  private readonly healthTargetsStmt;
  private readonly updateHealthStmt;
  private readonly healthCheckIntervalMs: number;
  private healthTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    dbPath: string,
    cacheTtlSeconds = CACHE_TTL_SECONDS,
    healthCheckIntervalSeconds = HEALTH_CHECK_INTERVAL_SECONDS,
  ) {
    this.db = openDatabase(dbPath);
    this.cacheTtlMs = Math.max(0, cacheTtlSeconds) * 1000;
    this.healthCheckIntervalMs = Math.max(0, healthCheckIntervalSeconds) * 1000;

    this.getByNameStmt = this.db.query<StoredRecord, [string]>(`
      SELECT id, type, ttl, value, weight, geo_cidrs, enabled, healthcheck_url, healthy
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
    this.healthTargetsStmt = this.db.query<{ id: number; healthcheck_url: string }, []>(`
      SELECT id, healthcheck_url
      FROM records
      WHERE enabled = 1
        AND healthcheck_url IS NOT NULL
        AND TRIM(healthcheck_url) <> ''
    `);
    this.updateHealthStmt = this.db.query<{ changes: number }, [number, string | null, number]>(`
      UPDATE records
      SET healthy = ?1,
          last_health_error = ?2,
          last_health_check_at = CURRENT_TIMESTAMP
      WHERE id = ?3
    `);
    this.startHealthChecks();
  }

  lookup(name: string, qtype: number, clientIp: string): LookupResult {
    const fqdn = normalizeFqdn(name);
    const bare = normalizeDomain(fqdn);
    const now = Date.now();
    const cached = this.cache.get(fqdn);
    const zoneName = this.resolveZoneName(bare);
    if (cached && now < cached.expiresAt) {
      const selected = this.selectRecordsForQuery(cached.records, qtype, clientIp);
      return {
        zoneName,
        nameExists: cached.records.length > 0,
        records: selected,
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

    const selected = this.selectRecordsForQuery(records, qtype, clientIp);
    return {
      zoneName,
      nameExists: records.length > 0,
      records: selected,
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

  private selectRecordsForQuery(records: StoredRecord[], qtype: number, clientIp: string): DnsRecord[] {
    const enabled = records.filter((record) => record.enabled === 1);
    if (enabled.length === 0) return [];

    const toDnsRecord = (record: StoredRecord): DnsRecord => ({
      type: record.type,
      ttl: record.ttl,
      value: record.value,
    });

    if (qtype === QTYPE.ANY) {
      const out: DnsRecord[] = [];
      const byType = new Map<string, StoredRecord[]>();
      for (const record of enabled) {
        const list = byType.get(record.type) ?? [];
        list.push(record);
        byType.set(record.type, list);
      }
      for (const [type, list] of byType.entries()) {
        if (type === "A" || type === "AAAA" || type === "CNAME") {
          const picked = this.pickRouted(list, clientIp);
          if (picked) out.push(toDnsRecord(picked));
        } else {
          for (const record of list) out.push(toDnsRecord(record));
        }
      }
      return out;
    }

    if (qtype === QTYPE.A || qtype === QTYPE.AAAA || qtype === QTYPE.CNAME) {
      const cname = enabled.filter((record) => record.type === "CNAME");
      if (cname.length > 0) {
        const pickedCname = this.pickRouted(cname, clientIp);
        return pickedCname ? [toDnsRecord(pickedCname)] : [];
      }

      const targetType = qtype === QTYPE.A ? "A" : qtype === QTYPE.AAAA ? "AAAA" : "CNAME";
      const candidates = enabled.filter((record) => record.type === targetType);
      const picked = this.pickRouted(candidates, clientIp);
      return picked ? [toDnsRecord(picked)] : [];
    }

    const exactType = this.qtypeToType(qtype);
    if (!exactType) return [];
    return enabled
      .filter((record) => record.type === exactType)
      .map(toDnsRecord);
  }

  private qtypeToType(qtype: number): DnsRecord["type"] | null {
    if (qtype === QTYPE.NS) return "NS";
    if (qtype === QTYPE.SOA) return "SOA";
    if (qtype === QTYPE.PTR) return "PTR";
    if (qtype === QTYPE.MX) return "MX";
    if (qtype === QTYPE.TXT) return "TXT";
    if (qtype === QTYPE.SRV) return "SRV";
    if (qtype === QTYPE.CAA) return "CAA";
    return null;
  }

  private pickRouted(records: StoredRecord[], clientIp: string): StoredRecord | null {
    if (records.length === 0) return null;
    let pool = records;
    if (clientIp) {
      const geoMatches = records.filter(
        (record) => record.geo_cidrs.trim() && ipMatchesAnyCidr(clientIp, record.geo_cidrs),
      );
      if (geoMatches.length > 0) {
        pool = geoMatches;
      } else {
        const nonGeo = records.filter((record) => !record.geo_cidrs.trim());
        if (nonGeo.length > 0) pool = nonGeo;
      }
    }

    const healthyPool = this.filterHealthy(pool);
    return this.pickWeighted(healthyPool);
  }

  private filterHealthy(records: StoredRecord[]): StoredRecord[] {
    const usable = records.filter((record) => {
      if (!record.healthcheck_url?.trim()) return true;
      return record.healthy === 1;
    });
    return usable.length > 0 ? usable : records;
  }

  private pickWeighted(records: StoredRecord[]): StoredRecord | null {
    if (records.length === 0) return null;
    const total = records.reduce((sum, record) => sum + Math.max(1, record.weight), 0);
    let roll = Math.floor(Math.random() * total);
    for (const record of records) {
      roll -= Math.max(1, record.weight);
      if (roll < 0) return record;
    }
    return records[records.length - 1] ?? null;
  }

  private startHealthChecks() {
    if (this.healthCheckIntervalMs <= 0) return;
    this.healthTimer = setInterval(() => {
      void this.runHealthChecks();
    }, this.healthCheckIntervalMs);
  }

  private async runHealthChecks() {
    const targets = this.healthTargetsStmt.all();
    for (const target of targets) {
      let healthy = 0;
      let error: string | null = null;
      try {
        const response = await fetch(target.healthcheck_url, {
          method: "GET",
          signal: AbortSignal.timeout(Math.max(250, HEALTH_CHECK_TIMEOUT_MS)),
        });
        healthy = response.status < 500 ? 1 : 0;
        if (healthy === 0) error = `status:${response.status}`;
      } catch (err) {
        healthy = 0;
        error = err instanceof Error ? err.message.slice(0, 200) : "health-check failed";
      }
      this.updateHealthStmt.run(healthy, error, target.id);
      this.cache.clear();
    }
  }

  close() {
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
      this.healthTimer = null;
    }
    this.db.close();
  }
}
