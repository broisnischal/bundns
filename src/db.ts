import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { Database } from "bun:sqlite";

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
      type TEXT NOT NULL CHECK (type IN ('A', 'AAAA', 'CNAME')),
      ttl INTEGER NOT NULL,
      value TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
      UNIQUE (domain_id, fqdn, type)
    )
  `);

  db.run(`
    CREATE INDEX IF NOT EXISTS idx_records_fqdn_type ON records (fqdn, type)
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS ddns_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      domain_id INTEGER NOT NULL,
      fqdn TEXT NOT NULL,
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

  seedDefaults(db);
  return db;
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
  });
  tx();
}
