import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { Database } from "bun:sqlite";

const SUPPORTED_RECORD_TYPES = ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "SRV", "PTR"];

export function normalizeFqdn(input: string): string {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) {
    throw new Error("FQDN cannot be empty");
  }
  return trimmed.endsWith(".") ? trimmed : `${trimmed}.`;
}

export function normalizeDomain(input: string): string {
  const fqdn = normalizeFqdn(input);
  return fqdn.slice(0, -1);
}

export function hostToFqdn(host: string, domain: string): string {
  const h = host.trim().toLowerCase();
  if (!h || h === "@") {
    return normalizeFqdn(domain);
  }
  return normalizeFqdn(`${h}.${domain}`);
}

export function openDatabase(dbPath: string) {
  mkdirSync(dirname(dbPath), { recursive: true });
  const db = new Database(dbPath, { create: true, strict: true });

  db.run("PRAGMA journal_mode = WAL;");
  db.run("PRAGMA synchronous = NORMAL;");
  db.run("PRAGMA temp_store = MEMORY;");
  db.run("PRAGMA foreign_keys = ON;");

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS api_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      label TEXT NOT NULL DEFAULT 'default',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_used_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS domains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      name TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain_id INTEGER,
      fqdn TEXT NOT NULL,
      type TEXT NOT NULL CHECK (type IN ('${SUPPORTED_RECORD_TYPES.join("', '")}')),
      ttl INTEGER NOT NULL,
      value TEXT NOT NULL,
      weight INTEGER NOT NULL DEFAULT 100,
      geo_cidrs TEXT NOT NULL DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 1,
      healthcheck_url TEXT,
      healthy INTEGER NOT NULL DEFAULT 1,
      last_health_check_at TEXT,
      last_health_error TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
      UNIQUE (domain_id, fqdn, type, value)
    )
  `);

  db.run(`
    CREATE INDEX IF NOT EXISTS idx_records_fqdn_type ON records (fqdn, type)
  `);
  db.run(`
    CREATE INDEX IF NOT EXISTS idx_records_domain_fqdn_type ON records (domain_id, fqdn, type)
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS ddns_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      domain_id INTEGER NOT NULL,
      fqdn TEXT NOT NULL,
      token_value TEXT NOT NULL DEFAULT '',
      token_hash TEXT NOT NULL UNIQUE,
      ttl INTEGER NOT NULL DEFAULT 60,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS ddns_updates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ddns_token_id INTEGER NOT NULL,
      ip TEXT NOT NULL,
      previous_value TEXT,
      new_value TEXT NOT NULL,
      user_agent TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (ddns_token_id) REFERENCES ddns_tokens(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS domain_access_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      domain_id INTEGER NOT NULL,
      label TEXT NOT NULL DEFAULT 'default',
      key_hash TEXT NOT NULL UNIQUE,
      key_value TEXT NOT NULL DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
    )
  `);

  migrateLegacyRecordsTableIfNeeded(db);
  migrateRecordColumnsIfNeeded(db);
  migrateDdnsTokensTableIfNeeded(db);
  seedDefaults(db);
  return db;
}

function migrateLegacyRecordsTableIfNeeded(db: Database) {
  const tableDef = db
    .query<{ sql: string }, [string]>(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1`)
    .get("records");
  const sql = tableDef?.sql ?? "";

  const hasExtendedTypes = sql.includes("SOA") && sql.includes("NS");
  const hasExtendedUnique = sql.includes("UNIQUE (domain_id, fqdn, type, value)");
  if (hasExtendedTypes && hasExtendedUnique) {
    return;
  }

  const tx = db.transaction(() => {
    db.run(`ALTER TABLE records RENAME TO records_old`);
    db.run(`
      CREATE TABLE records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER,
        fqdn TEXT NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('${SUPPORTED_RECORD_TYPES.join("', '")}')),
        ttl INTEGER NOT NULL,
        value TEXT NOT NULL,
        weight INTEGER NOT NULL DEFAULT 100,
        geo_cidrs TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        healthcheck_url TEXT,
        healthy INTEGER NOT NULL DEFAULT 1,
        last_health_check_at TEXT,
        last_health_error TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
        UNIQUE (domain_id, fqdn, type, value)
      )
    `);
    db.run(`
      INSERT OR IGNORE INTO records (
        id, domain_id, fqdn, type, ttl, value, weight, geo_cidrs, enabled, healthcheck_url, healthy,
        last_health_check_at, last_health_error, created_at, updated_at
      )
      SELECT
        id, domain_id, fqdn, type, ttl, value,
        100, '', 1, NULL, 1, NULL, NULL, created_at, updated_at
      FROM records_old
      WHERE type IN ('${SUPPORTED_RECORD_TYPES.join("', '")}')
    `);
    db.run(`DROP TABLE records_old`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_records_fqdn_type ON records (fqdn, type)`);
    db.run(
      `CREATE INDEX IF NOT EXISTS idx_records_domain_fqdn_type ON records (domain_id, fqdn, type)`,
    );
  });
  tx();
}

function migrateRecordColumnsIfNeeded(db: Database) {
  const columns = new Set(
    db
      .query<{ name: string }, []>(`PRAGMA table_info(records)`)
      .all()
      .map((row) => row.name),
  );
  if (!columns.has("weight")) {
    db.run(`ALTER TABLE records ADD COLUMN weight INTEGER NOT NULL DEFAULT 100`);
  }
  if (!columns.has("geo_cidrs")) {
    db.run(`ALTER TABLE records ADD COLUMN geo_cidrs TEXT NOT NULL DEFAULT ''`);
  }
  if (!columns.has("enabled")) {
    db.run(`ALTER TABLE records ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1`);
  }
  if (!columns.has("healthcheck_url")) {
    db.run(`ALTER TABLE records ADD COLUMN healthcheck_url TEXT`);
  }
  if (!columns.has("healthy")) {
    db.run(`ALTER TABLE records ADD COLUMN healthy INTEGER NOT NULL DEFAULT 1`);
  }
  if (!columns.has("last_health_check_at")) {
    db.run(`ALTER TABLE records ADD COLUMN last_health_check_at TEXT`);
  }
  if (!columns.has("last_health_error")) {
    db.run(`ALTER TABLE records ADD COLUMN last_health_error TEXT`);
  }
  db.run(`CREATE INDEX IF NOT EXISTS idx_records_healthcheck ON records (enabled, healthcheck_url)`);
}

function migrateDdnsTokensTableIfNeeded(db: Database) {
  const columns = db
    .query<{ name: string }, []>(`PRAGMA table_info(ddns_tokens)`)
    .all()
    .map((row) => row.name);
  if (!columns.includes("token_value")) {
    db.run(`ALTER TABLE ddns_tokens ADD COLUMN token_value TEXT NOT NULL DEFAULT ''`);
  }
}

function seedDefaults(db: Database) {
  const tx = db.transaction(() => {
    db.run(`INSERT OR IGNORE INTO domains (user_id, name) VALUES (NULL, ?1)`, ["example.local"]);

    const domain = db
      .query<{ id: number }, [string]>(`SELECT id FROM domains WHERE name = ?1 LIMIT 1`)
      .get("example.local");

    const domainId = domain?.id ?? null;
    db.run(
      `
        INSERT OR IGNORE INTO records (domain_id, fqdn, type, ttl, value)
        VALUES (?1, ?2, ?3, ?4, ?5)
      `,
      [domainId, "example.local.", "A", 60, "127.0.0.1"],
    );
    db.run(
      `
        INSERT OR IGNORE INTO records (domain_id, fqdn, type, ttl, value)
        VALUES (?1, ?2, ?3, ?4, ?5)
      `,
      [domainId, "example.local.", "AAAA", 60, "::1"],
    );
    db.run(
      `
        INSERT OR IGNORE INTO records (domain_id, fqdn, type, ttl, value)
        VALUES (?1, ?2, ?3, ?4, ?5)
      `,
      [domainId, "api.example.local.", "CNAME", 60, "example.local."],
    );
    db.run(
      `
        INSERT OR IGNORE INTO records (domain_id, fqdn, type, ttl, value)
        VALUES (?1, ?2, ?3, ?4, ?5)
      `,
      [domainId, "example.local.", "NS", 300, "ns1.example.local."],
    );
    db.run(
      `
        INSERT OR IGNORE INTO records (domain_id, fqdn, type, ttl, value)
        VALUES (?1, ?2, ?3, ?4, ?5)
      `,
      [domainId, "ns1.example.local.", "A", 300, "127.0.0.1"],
    );
    db.run(
      `
        INSERT OR IGNORE INTO records (domain_id, fqdn, type, ttl, value)
        VALUES (?1, ?2, ?3, ?4, ?5)
      `,
      [
        domainId,
        "example.local.",
        "SOA",
        300,
        "ns1.example.local. hostmaster.example.local. 2026022601 3600 900 1209600 300",
      ],
    );
  });
  tx();
}
