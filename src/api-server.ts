import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { up } from "up-fetch";
import { openDatabase, hostToFqdn, normalizeDomain, normalizeFqdn } from "./db";
import { isValidCidr, parseCidrList } from "./net-utils";
import { buildOpenApiSpec, scalarHtml } from "./openapi";

const API_HOST = process.env.API_HOST ?? "0.0.0.0";
const API_PORT = Number(process.env.API_PORT ?? 3000);
const DB_PATH = process.env.DNS_DB_PATH ?? "./data/dns.sqlite";
const UI_VERSION = "v2.0";
const DEFAULT_NS_HOST = process.env.DEFAULT_NS_HOST ?? "ns1";
const DEFAULT_NS_IP = process.env.DEFAULT_NS_IP ?? "127.0.0.1";

type ApiUser = { id: number; email: string };
type AuthToken = { user_id: number };
type DomainRow = { id: number; user_id: number | null; name: string; created_at: string };
type RecordRow = {
  id: number;
  domain_id: number | null;
  fqdn: string;
  type: "A" | "AAAA" | "CNAME" | "NS" | "SOA" | "MX" | "TXT" | "CAA" | "SRV" | "PTR";
  ttl: number;
  value: string;
  weight: number;
  geo_cidrs: string;
  enabled: number;
  healthcheck_url: string | null;
  healthy: number;
  last_health_check_at: string | null;
  last_health_error: string | null;
  created_at: string;
  updated_at: string;
};
type DdnsTokenRow = {
  id: number;
  user_id: number;
  domain_id: number;
  fqdn: string;
  token_value: string;
  ttl: number;
  enabled: number;
  created_at: string;
};
type SessionUser = { id: number; email: string };

const db = openDatabase(DB_PATH);

const insertUserStmt = db.query<{ lastInsertRowid: number }, [string, string]>(
  `INSERT INTO users (email, password_hash) VALUES (?1, ?2)`,
);
const findUserByEmailStmt = db.query<{ id: number; email: string; password_hash: string }, [string]>(
  `SELECT id, email, password_hash FROM users WHERE email = ?1 LIMIT 1`,
);
const insertApiTokenStmt = db.query<{ lastInsertRowid: number }, [number, string, string]>(
  `INSERT INTO api_tokens (user_id, token_hash, label) VALUES (?1, ?2, ?3)`,
);
const findTokenStmt = db.query<AuthToken, [string]>(
  `SELECT user_id FROM api_tokens WHERE token_hash = ?1 LIMIT 1`,
);
const touchTokenStmt = db.query<{ changes: number }, [string]>(
  `UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_hash = ?1`,
);
const createDomainStmt = db.query<{ lastInsertRowid: number }, [number, string]>(
  `INSERT INTO domains (user_id, name) VALUES (?1, ?2)`,
);
const listDomainsStmt = db.query<DomainRow, [number]>(
  `SELECT id, user_id, name, created_at FROM domains WHERE user_id = ?1 ORDER BY id DESC`,
);
const getDomainStmt = db.query<DomainRow, [number, number]>(
  `SELECT id, user_id, name, created_at FROM domains WHERE id = ?1 AND user_id = ?2 LIMIT 1`,
);
const insertRecordStmt = db.query<
  { lastInsertRowid: number },
  [number, string, string, number, string, number, string, number, string | null]
>(
  `
    INSERT INTO records (domain_id, fqdn, type, ttl, value, weight, geo_cidrs, enabled, healthcheck_url)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
    ON CONFLICT (domain_id, fqdn, type, value)
    DO UPDATE SET
      ttl = excluded.ttl,
      weight = excluded.weight,
      geo_cidrs = excluded.geo_cidrs,
      enabled = excluded.enabled,
      healthcheck_url = excluded.healthcheck_url,
      updated_at = CURRENT_TIMESTAMP
  `,
);
const insertRecordIfMissingStmt = db.query<{ changes: number }, [number, string, string, number, string]>(
  `
    INSERT OR IGNORE INTO records (domain_id, fqdn, type, ttl, value)
    VALUES (?1, ?2, ?3, ?4, ?5)
  `,
);
const listRecordsStmt = db.query<RecordRow, [number]>(
  `
    SELECT
      id, domain_id, fqdn, type, ttl, value, weight, geo_cidrs, enabled, healthcheck_url, healthy,
      last_health_check_at, last_health_error, created_at, updated_at
    FROM records
    WHERE domain_id = ?1
    ORDER BY id DESC
  `,
);
const getRecordForOwnerStmt = db.query<RecordRow, [number, number]>(
  `
    SELECT
      r.id, r.domain_id, r.fqdn, r.type, r.ttl, r.value, r.weight, r.geo_cidrs, r.enabled,
      r.healthcheck_url, r.healthy, r.last_health_check_at, r.last_health_error, r.created_at, r.updated_at
    FROM records r
    JOIN domains d ON d.id = r.domain_id
    WHERE r.id = ?1 AND d.user_id = ?2
    LIMIT 1
  `,
);
const updateRecordStmt = db.query<
  { changes: number },
  [number, number, string, string, number, string, number, string, number, string | null]
>(
  `
    UPDATE records
    SET
      fqdn = ?3,
      type = ?4,
      ttl = ?5,
      value = ?6,
      weight = ?7,
      geo_cidrs = ?8,
      enabled = ?9,
      healthcheck_url = ?10,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?1 AND domain_id = ?2
  `,
);
const deleteRecordStmt = db.query<{ changes: number }, [number]>(`DELETE FROM records WHERE id = ?1`);
const createDdnsTokenStmt = db.query<
  { lastInsertRowid: number },
  [number, number, string, string, string, number]
>(
  `
    INSERT INTO ddns_tokens (user_id, domain_id, fqdn, token_value, token_hash, ttl)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)
  `,
);
const findDdnsTokenStmt = db.query<DdnsTokenRow, [string]>(
  `
    SELECT id, user_id, domain_id, fqdn, token_value, ttl, enabled, created_at
    FROM ddns_tokens
    WHERE token_hash = ?1
    LIMIT 1
  `,
);
const listDdnsTokensForDomainStmt = db.query<
  DdnsTokenRow,
  [number, number]
>(
  `
    SELECT t.id, t.user_id, t.domain_id, t.fqdn, t.token_value, t.ttl, t.enabled, t.created_at
    FROM ddns_tokens t
    JOIN domains d ON d.id = t.domain_id
    WHERE t.domain_id = ?1 AND d.user_id = ?2
    ORDER BY t.id DESC
  `,
);
const getDdnsTokenForOwnerStmt = db.query<DdnsTokenRow, [number, number]>(
  `
    SELECT t.id, t.user_id, t.domain_id, t.fqdn, t.token_value, t.ttl, t.enabled, t.created_at
    FROM ddns_tokens t
    JOIN domains d ON d.id = t.domain_id
    WHERE t.id = ?1 AND d.user_id = ?2
    LIMIT 1
  `,
);
const deleteDdnsTokenStmt = db.query<{ changes: number }, [number]>(
  `DELETE FROM ddns_tokens WHERE id = ?1`,
);
const findRecordValueStmt = db.query<{ value: string }, [number, string]>(
  `SELECT value FROM records WHERE domain_id = ?1 AND fqdn = ?2 AND type = 'A' LIMIT 1`,
);
const deleteRecordsByNameTypeStmt = db.query<{ changes: number }, [number, string, string]>(
  `DELETE FROM records WHERE domain_id = ?1 AND fqdn = ?2 AND type = ?3`,
);
const insertDdnsUpdateStmt = db.query<{ changes: number }, [number, string, string | null, string, string]>(
  `
    INSERT INTO ddns_updates (ddns_token_id, ip, previous_value, new_value, user_agent)
    VALUES (?1, ?2, ?3, ?4, ?5)
  `,
);

function tokenHash(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

function randomToken(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "")}${crypto.randomUUID().replaceAll("-", "")}`;
}

function json(data: unknown, init?: ResponseInit) {
  return Response.json(data, init);
}

async function readBody<T>(req: Request): Promise<T | null> {
  try {
    return (await req.json()) as T;
  } catch {
    return null;
  }
}

function invalid(message: string, status = 400) {
  return json({ error: message }, { status });
}

async function authenticate(req: Request): Promise<ApiUser | null> {
  const auth = req.headers.get("authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  const raw = auth.slice("Bearer ".length).trim();
  if (!raw) return null;

  const hash = tokenHash(raw);
  const token = findTokenStmt.get(hash);
  if (!token) return null;
  touchTokenStmt.run(hash);

  const user = db
    .query<ApiUser, [number]>(`SELECT id, email FROM users WHERE id = ?1 LIMIT 1`)
    .get(token.user_id);
  return user ?? null;
}

function normalizeRecordValue(type: string, value: string) {
  const trimmed = value.trim();
  if (type === "A") {
    if (isIP(trimmed) !== 4) throw new Error("Invalid IPv4 value");
    return trimmed;
  }
  if (type === "AAAA") {
    if (isIP(trimmed) !== 6) throw new Error("Invalid IPv6 value");
    return trimmed;
  }
  if (type === "CNAME") {
    return normalizeFqdn(trimmed);
  }
  if (type === "NS") {
    return normalizeFqdn(trimmed);
  }
  if (type === "PTR") {
    return normalizeFqdn(trimmed);
  }
  if (type === "SOA") {
    const parts = trimmed.split(/\s+/);
    if (parts.length !== 7) throw new Error("SOA must be: mname rname serial refresh retry expire minimum");
    const numbers = parts.slice(2).map((part) => Number(part));
    if (numbers.some((n) => !Number.isInteger(n) || n < 0 || n > 0xffffffff)) {
      throw new Error("Invalid SOA numeric fields");
    }
    return `${normalizeFqdn(parts[0]!)} ${normalizeFqdn(parts[1]!)} ${numbers.join(" ")}`;
  }
  if (type === "MX") {
    const parts = trimmed.split(/\s+/);
    if (parts.length !== 2) throw new Error("MX must be: preference exchange");
    const preference = Number(parts[0]);
    if (!Number.isInteger(preference) || preference < 0 || preference > 65535) {
      throw new Error("Invalid MX preference");
    }
    return `${preference} ${normalizeFqdn(parts[1]!)}`;
  }
  if (type === "TXT") {
    if (!trimmed) throw new Error("TXT value cannot be empty");
    return trimmed;
  }
  if (type === "CAA") {
    const match = trimmed.match(/^(\d+)\s+([a-zA-Z0-9-]+)\s+(.+)$/);
    if (!match) throw new Error("CAA must be: flags tag value");
    const flags = Number(match[1]);
    if (!Number.isInteger(flags) || flags < 0 || flags > 255) {
      throw new Error("Invalid CAA flags");
    }
    return `${flags} ${match[2]} ${match[3]}`;
  }
  if (type === "SRV") {
    const parts = trimmed.split(/\s+/);
    if (parts.length !== 4) throw new Error("SRV must be: priority weight port target");
    const [priority = -1, weight = -1, port = -1] = parts.slice(0, 3).map((part) => Number(part));
    if (
      [priority, weight, port].some(
        (v) => !Number.isInteger(v) || v < 0 || v > 65535,
      )
    ) {
      throw new Error("Invalid SRV numeric fields");
    }
    return `${priority} ${weight} ${port} ${normalizeFqdn(parts[3]!)}`;
  }
  throw new Error("Unsupported record type");
}

function normalizeRoutingOptions(input: {
  weight?: number;
  geoCidrs?: string;
  enabled?: boolean;
  healthcheckUrl?: string;
}) {
  const weight = Number(input.weight ?? 100);
  if (!Number.isInteger(weight) || weight <= 0 || weight > 10000) {
    throw new Error("weight must be an integer between 1 and 10000");
  }

  const geoRaw = String(input.geoCidrs ?? "").trim();
  const geoList = parseCidrList(geoRaw);
  for (const cidr of geoList) {
    if (!isValidCidr(cidr)) {
      throw new Error(`Invalid CIDR in geoCidrs: ${cidr}`);
    }
  }
  const geoCidrs = geoList.join(",");
  const enabled = input.enabled === false ? 0 : 1;
  const healthcheckUrlRaw = String(input.healthcheckUrl ?? "").trim();
  let healthcheckUrl: string | null = null;
  if (healthcheckUrlRaw) {
    const parsed = new URL(healthcheckUrlRaw);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("healthcheckUrl must use http or https");
    }
    healthcheckUrl = parsed.toString();
  }
  return { weight, geoCidrs, enabled, healthcheckUrl };
}

function getClientIp(req: Request) {
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0]?.trim() ?? "";
  }
  const realIp = req.headers.get("x-real-ip");
  return realIp?.trim() ?? "";
}

function serverUrlFor(req: Request) {
  const url = new URL(req.url);
  return `${url.protocol}//${url.host}`;
}

function parseCookies(req: Request) {
  const raw = req.headers.get("cookie") ?? "";
  const out = new Map<string, string>();
  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (!k || rest.length === 0) continue;
    out.set(k, decodeURIComponent(rest.join("=")));
  }
  return out;
}

function getSessionToken(req: Request) {
  return parseCookies(req).get("api_token") ?? "";
}

function getSessionUserByToken(token: string): SessionUser | null {
  if (!token) return null;
  const tokenRow = findTokenStmt.get(tokenHash(token));
  if (!tokenRow) return null;
  touchTokenStmt.run(tokenHash(token));
  return (
    db.query<SessionUser, [number]>(`SELECT id, email FROM users WHERE id = ?1 LIMIT 1`).get(tokenRow.user_id) ??
    null
  );
}

function redirect(to: string, headers?: Record<string, string>) {
  return new Response(null, {
    status: 302,
    headers: {
      location: to,
      ...(headers ?? {}),
    },
  });
}

function setTokenCookie(token: string) {
  return `api_token=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`;
}

function clearTokenCookie() {
  return "api_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
}

function safeJson(value: unknown) {
  return JSON.stringify(value).replaceAll("<", "\\u003c");
}

function appHtml(state: {
  user: SessionUser | null;
  token: string;
  domains: DomainRow[];
  records: RecordRow[];
  ddnsTokens: DdnsTokenRow[];
  selectedDomainId: number | null;
}) {
  const initial = safeJson({
    user: state.user,
    token: state.token,
    domains: state.domains,
    records: state.records,
    ddnsTokens: state.ddnsTokens,
    selectedDomainId: state.selectedDomainId,
  });

  if (!state.user) {
    return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DNS Control Panel</title>
    <style>
      body { font-family: system-ui, sans-serif; max-width: 920px; margin: 2rem auto; padding: 0 1rem; }
      .card { border: 1px solid #ddd; border-radius: 12px; padding: 1rem; margin-bottom: 1rem; }
      input, select, button { padding: .55rem .7rem; margin: .25rem 0; width: 100%; box-sizing: border-box; }
      .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
      pre { background: #111; color: #eee; padding: .7rem; border-radius: 8px; overflow: auto; }
    </style>
  </head>
  <body>
    <h1>DNS Control Panel</h1>
    <p>Login or register to manage domains and records.</p>
    <div class="grid">
      <form class="card" method="post" action="/app/register">
        <h2>Register</h2>
        <input name="email" type="email" placeholder="email" required />
        <input name="password" type="password" placeholder="password (min 8 chars)" required />
        <button type="submit">Register</button>
      </form>
      <form class="card" method="post" action="/app/login">
        <h2>Login</h2>
        <input name="email" type="email" placeholder="email" required />
        <input name="password" type="password" placeholder="password" required />
        <button type="submit">Login</button>
      </form>
    </div>
  </body>
</html>`;
  }

  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DNS Control Panel</title>
    <style>
      :root { --border: #d9d9d9; --muted: #5f6368; --ok: #0a7c25; --err: #b00020; --bg: #ffffff; --text: #1f2937; --panel: #fafafa; }
      html, body { background: var(--bg); color: var(--text); }
      body { font-family: Inter, system-ui, sans-serif; max-width: 1220px; margin: 1.2rem auto; padding: 0 1rem; line-height: 1.4; }
      .row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 1rem; }
      .card { border: 1px solid var(--border); border-radius: 12px; padding: 1rem; background: var(--panel); }
      .subtle { color: var(--muted); font-size: .92rem; margin-top: .25rem; }
      .badge { border: 1px solid var(--border); border-radius: 999px; padding: .2rem .6rem; font-size: .8rem; }
      input, select, button { padding: .58rem .7rem; margin: .2rem 0; width: 100%; box-sizing: border-box; border-radius: 8px; border: 1px solid var(--border); font-size: .95rem; background: #fff; color: var(--text); }
      button { cursor: pointer; background: #2563eb; color: #fff; border-color: #2563eb; }
      button.secondary { background: #fff; color: var(--text); border-color: var(--border); }
      .stack { display: grid; gap: .55rem; }
      .field { display: grid; gap: .2rem; }
      .field-label { font-size: .88rem; font-weight: 600; color: #374151; }
      .helper { font-size: .82rem; color: var(--muted); margin-top: .1rem; }
      .form-split { display: grid; grid-template-columns: 1fr 1fr; gap: .8rem; }
      .settings-box { border: 1px dashed #cbd5e1; border-radius: 10px; padding: .6rem; background: #fff; }
      .check-inline { display: flex; align-items: center; gap: .5rem; font-size: .9rem; }
      .check-inline input { width: auto; margin: 0; }
      .preset-row { display: flex; gap: .4rem; flex-wrap: wrap; }
      .preset-row button { width: auto; padding: .35rem .55rem; font-size: .83rem; }
      table { width: 100%; border-collapse: collapse; }
      th, td { border-bottom: 1px solid #ececec; text-align: left; padding: .55rem; font-size: .93rem; vertical-align: top; }
      th { font-weight: 600; }
      td.actions { width: 150px; }
      .inline-actions { display: flex; gap: .4rem; }
      .inline-actions button { width: auto; margin: 0; padding: .35rem .65rem; }
      pre { background: #f3f4f6; color: #111827; border-radius: 8px; padding: .6rem; overflow: auto; border: 1px solid #e5e7eb; }
      #msg { min-height: 1.2rem; color: var(--ok); font-weight: 500; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
      .section-title { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
      .modal-backdrop {
        position: fixed;
        inset: 0;
        background: rgba(15, 23, 42, 0.35);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 1rem;
        z-index: 50;
      }
      .modal-backdrop[hidden] { display: none !important; }
      .modal-content {
        width: min(760px, 100%);
        max-height: 92vh;
        overflow: auto;
        background: #fff;
        border-radius: 12px;
        border: 1px solid var(--border);
        padding: 1rem;
      }
      .modal-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: .8rem;
      }
      .details-box {
        border: 1px solid #e5e7eb;
        border-radius: 10px;
        padding: .55rem .65rem;
        background: #fff;
      }
      .details-box summary {
        cursor: pointer;
        font-weight: 600;
        font-size: .92rem;
      }
      @media (max-width: 860px) {
        .form-split { grid-template-columns: 1fr; }
      }
    </style>
  </head>
  <body>
    <div class="row">
      <div>
        <h1>DNS Control Panel</h1>
        <div>Logged in as <strong>${state.user.email}</strong> <span class="badge">${UI_VERSION}</span></div>
        <div class="subtle">Manage records, DDNS tokens, and live updates in one place.</div>
      </div>
      <div class="row">
        <a href="/docs">API Docs</a>
        <form method="post" action="/app/logout"><button type="submit">Logout</button></form>
      </div>
    </div>

    <p id="msg"></p>

    <div class="grid">
      <div class="card">
        <h3>Create Domain</h3>
        <form id="create-domain-form">
          <input name="domain" placeholder="example.com" required />
          <button type="submit">Create Domain</button>
        </form>
      </div>

      <div class="card">
        <h3>Record Editor</h3>
        <div class="helper">Open the popup to create or edit records. Routing settings are available in Advanced section.</div>
        <button id="open-record-modal-btn" type="button">Create Record</button>
      </div>

      <div class="card">
        <h3>Create DDNS Token</h3>
        <form id="create-ddns-form">
          <select name="domainId" id="ddns-domain-select"></select>
          <input name="host" placeholder="home" />
          <input name="ttl" type="number" value="60" min="1" max="86400" />
          <button type="submit">Create Token</button>
        </form>
        <div class="subtle">Token is stored and shown here for easy client setup.</div>
        <pre id="ddns-token-output"></pre>
      </div>

      <div class="card">
        <h3>Update DDNS (Manual Test)</h3>
        <form id="update-ddns-form">
          <input name="token" placeholder="ddns token" required />
          <input name="ip" placeholder="1.2.3.4 (optional)" />
          <button type="submit">Update</button>
        </form>
      </div>
    </div>

    <div class="card" style="margin-top:1rem">
      <div class="section-title">
        <h3>Records</h3>
        <button id="refresh-btn" type="button" class="secondary">Refresh</button>
      </div>
      <table>
        <thead><tr><th>ID</th><th>FQDN</th><th>TYPE</th><th>TTL</th><th>VALUE</th><th>W</th><th>Geo CIDRs</th><th>Enabled</th><th>Health</th><th>Actions</th></tr></thead>
        <tbody id="records-body"></tbody>
      </table>
    </div>

    <div class="card" style="margin-top:1rem">
      <div class="section-title">
        <h3>DDNS Tokens</h3>
      </div>
      <table>
        <thead><tr><th>ID</th><th>FQDN</th><th>Token</th><th>TTL</th><th>Created</th><th>Actions</th></tr></thead>
        <tbody id="ddns-body"></tbody>
      </table>
    </div>

    <div id="record-modal" class="modal-backdrop" hidden>
      <div class="modal-content">
        <div class="modal-head">
          <h3 style="margin:0">Create / Update Record</h3>
          <button id="close-record-modal-btn" data-close-record-modal="1" type="button" class="secondary">Close</button>
        </div>
        <p id="record-modal-msg" class="helper"></p>
        <div class="helper" style="margin:.45rem 0 .8rem">Tip: For 60/40 traffic, create two records with same name/type and set weights 60 and 40.</div>
        <form id="create-record-form" class="stack">
          <input type="hidden" name="recordId" value="" />
          <label class="field">
            <span class="field-label">Domain</span>
            <select name="domainId" id="domain-select"></select>
          </label>
          <label class="field">
            <span class="field-label">Host</span>
            <input name="host" placeholder="@" value="@" />
            <span class="helper">@ = apex, or subdomain like app/api/ns1</span>
          </label>
          <label class="field">
            <span class="field-label">Type</span>
            <select name="type" id="record-type">
              <option>A</option>
              <option>AAAA</option>
              <option>CNAME</option>
              <option>NS</option>
              <option>SOA</option>
              <option>MX</option>
              <option>TXT</option>
              <option>CAA</option>
              <option>SRV</option>
              <option>PTR</option>
            </select>
          </label>
          <label class="field">
            <span class="field-label">TTL (seconds)</span>
            <input name="ttl" type="number" value="60" min="1" max="86400" />
          </label>
          <label class="field">
            <span class="field-label">Value</span>
            <input name="value" id="record-value" placeholder="1.2.3.4 or target.domain." required />
            <span class="helper" id="record-value-hint">For A: IPv4 (example: 1.2.3.4)</span>
          </label>
          <details class="details-box">
            <summary>Advanced: Routing / Health Settings</summary>
            <div class="stack" style="margin-top:.55rem">
              <label class="field">
                <span class="field-label">Weight</span>
                <input name="weight" id="record-weight" type="number" value="100" min="1" max="10000" />
              </label>
              <div class="preset-row">
                <button type="button" class="secondary" data-weight-preset="100">100%</button>
                <button type="button" class="secondary" data-weight-preset="60">60%</button>
                <button type="button" class="secondary" data-weight-preset="40">40%</button>
              </div>
              <label class="field">
                <span class="field-label">Geo CIDRs (optional)</span>
                <input name="geoCidrs" id="record-geo-cidrs" placeholder="1.2.0.0/16, 2a00::/12" />
                <span class="helper">Leave empty for global/default routing.</span>
              </label>
              <label class="field">
                <span class="field-label">Health Check URL (optional)</span>
                <input name="healthcheckUrl" id="record-health-url" placeholder="https://example.com/health" />
                <span class="helper">Used to remove unhealthy targets from weighted pools.</span>
              </label>
              <label class="check-inline"><input name="enabled" type="checkbox" checked /> Record enabled</label>
            </div>
          </details>
          <div class="inline-actions">
            <button type="submit" id="record-submit-btn">Save Record</button>
            <button type="button" data-close-record-modal="1" class="secondary" id="record-cancel-btn">Cancel</button>
          </div>
        </form>
      </div>
    </div>

    <script>window.__APP_STATE__ = ${initial};</script>
    <script type="module" src="/app/client.js"></script>
  </body>
</html>`;
}

function appClientJs() {
  return `import { up } from "https://esm.sh/up-fetch@2.5.1";

const state = window.__APP_STATE__ ?? { user: null, token: "", domains: [], records: [], ddnsTokens: [], selectedDomainId: null };
const msg = document.getElementById("msg");
const recordsBody = document.getElementById("records-body");
const ddnsBody = document.getElementById("ddns-body");
const domainSelect = document.getElementById("domain-select");
const ddnsDomainSelect = document.getElementById("ddns-domain-select");
const tokenOutput = document.getElementById("ddns-token-output");
const recordForm = document.getElementById("create-record-form");
const recordSubmitBtn = document.getElementById("record-submit-btn");
const recordCancelBtn = document.getElementById("record-cancel-btn");
const updateDdnsForm = document.getElementById("update-ddns-form");
const openRecordModalBtn = document.getElementById("open-record-modal-btn");
const closeRecordModalBtn = document.getElementById("close-record-modal-btn");
const recordModal = document.getElementById("record-modal");
const recordModalMsg = document.getElementById("record-modal-msg");
const recordTypeSelect = document.getElementById("record-type");
const recordValueInput = document.getElementById("record-value");
const recordValueHint = document.getElementById("record-value-hint");
const recordWeightInput = document.getElementById("record-weight");

const upfetch = up(fetch, () => ({
  baseUrl: window.location.origin,
  headers: state.token ? { Authorization: "Bearer " + state.token } : {},
  retry: { attempts: 1, delay: 200 },
}));

function setMsg(text, isError = false) {
  if (!msg) return;
  msg.textContent = text;
  msg.style.color = isError ? "#b00020" : "#0a7c25";
}

function setRecordModalMsg(text = "", isError = false) {
  if (!recordModalMsg) return;
  recordModalMsg.textContent = text;
  recordModalMsg.style.color = isError ? "#b00020" : "#0a7c25";
}

function fillDomainSelect(selectEl) {
  if (!selectEl) return;
  selectEl.innerHTML = "";
  for (const d of state.domains) {
    const o = document.createElement("option");
    o.value = String(d.id);
    o.textContent = d.name;
    if (state.selectedDomainId && d.id === state.selectedDomainId) o.selected = true;
    selectEl.appendChild(o);
  }
}

function fqdnToHost(fqdn, domainName) {
  const normalized = String(fqdn || "").replace(/\\.$/, "");
  const suffix = "." + String(domainName || "").replace(/\\.$/, "");
  if (normalized === String(domainName || "").replace(/\\.$/, "")) return "@";
  if (normalized.endsWith(suffix)) return normalized.slice(0, -suffix.length);
  return normalized;
}

function resetRecordForm() {
  if (!recordForm) return;
  recordForm.recordId.value = "";
  recordForm.host.value = "@";
  recordForm.type.value = "A";
  recordForm.ttl.value = "60";
  recordForm.value.value = "";
  recordForm.weight.value = "100";
  recordForm.geoCidrs.value = "";
  recordForm.healthcheckUrl.value = "";
  recordForm.enabled.checked = true;
  if (recordSubmitBtn) recordSubmitBtn.textContent = "Save Record";
  updateRecordTypeHint();
}

function updateRecordTypeHint() {
  if (!recordTypeSelect || !recordValueHint || !recordValueInput) return;
  const t = String(recordTypeSelect.value || "A");
  const hints = {
    A: ["For A: IPv4 (example: 1.2.3.4)", "1.2.3.4"],
    AAAA: ["For AAAA: IPv6 (example: 2001:db8::1)", "2001:db8::1"],
    CNAME: ["For CNAME: target FQDN", "target.example.com."],
    NS: ["For NS: nameserver FQDN", "ns1.example.com."],
    SOA: ["For SOA: mname rname serial refresh retry expire minimum", "ns1.example.com. hostmaster.example.com. 2026022601 3600 900 1209600 300"],
    MX: ["For MX: preference exchange", "10 mail.example.com."],
    TXT: ["For TXT: plain text value", "v=spf1 -all"],
    CAA: ["For CAA: flags tag value", "0 issue letsencrypt.org"],
    SRV: ["For SRV: priority weight port target", "10 5 5060 sip.example.com."],
    PTR: ["For PTR: target FQDN", "host.example.com."],
  };
  const selected = hints[t] || hints.A;
  recordValueHint.textContent = selected[0];
  recordValueInput.placeholder = selected[1];
}

function openRecordModal() {
  if (!recordModal) return;
  setRecordModalMsg("");
  recordModal.hidden = false;
}

function closeRecordModal() {
  if (!recordModal) return;
  recordModal.hidden = true;
  setRecordModalMsg("");
}

function renderRecords() {
  if (!recordsBody) return;
  recordsBody.innerHTML = "";
  for (const r of state.records) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + r.id + "</td>" +
      "<td class='mono'>" + r.fqdn + "</td>" +
      "<td>" + r.type + "</td>" +
      "<td>" + r.ttl + "</td>" +
      "<td class='mono'>" + r.value + "</td>" +
      "<td>" + (r.weight ?? 100) + "</td>" +
      "<td class='mono'>" + (r.geo_cidrs || "-") + "</td>" +
      "<td>" + (r.enabled === 1 ? "yes" : "no") + "</td>" +
      "<td>" + (r.healthcheck_url ? (r.healthy === 1 ? "healthy" : "unhealthy") : "-") + "</td>" +
      "<td class='actions'><div class='inline-actions'>" +
      "<button type='button' data-record-action='edit' data-record-id='" + r.id + "'>Edit</button>" +
      "<button type='button' data-record-action='delete' data-record-id='" + r.id + "'>Delete</button>" +
      "</div></td>";
    recordsBody.appendChild(tr);
  }
}

function renderDdnsTokens() {
  if (!ddnsBody) return;
  ddnsBody.innerHTML = "";
  for (const t of state.ddnsTokens) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + t.id + "</td>" +
      "<td class='mono'>" + t.fqdn + "</td>" +
      "<td class='mono'>" + (t.token_value || "(legacy token hidden)") + "</td>" +
      "<td>" + t.ttl + "</td>" +
      "<td>" + String(t.created_at || "").replace("T", " ").slice(0, 19) + "</td>" +
      "<td class='actions'><div class='inline-actions'>" +
      "<button type='button' data-token-action='use' data-token-value='" + encodeURIComponent(t.token_value || "") + "'>Use</button>" +
      "<button type='button' data-token-action='copy' data-token-value='" + encodeURIComponent(t.token_value || "") + "'>Copy</button>" +
      "<button type='button' data-token-action='delete' data-token-id='" + t.id + "'>Delete</button>" +
      "</div></td>";
    ddnsBody.appendChild(tr);
  }
}

async function reloadRecords(domainId) {
  const data = await upfetch("/api/domains/" + domainId + "/records");
  state.records = data.records ?? [];
  renderRecords();
}

async function reloadDdnsTokens(domainId) {
  const data = await upfetch("/api/domains/" + domainId + "/ddns-tokens");
  state.ddnsTokens = data.tokens ?? [];
  renderDdnsTokens();
}

async function reloadDomainData(domainId) {
  await Promise.all([reloadRecords(domainId), reloadDdnsTokens(domainId)]);
  state.selectedDomainId = domainId;
}

function startRecordEdit(recordId) {
  const record = state.records.find((r) => Number(r.id) === Number(recordId));
  const domain = state.domains.find((d) => d.id === Number(domainSelect?.value || state.selectedDomainId || 0));
  if (!record || !recordForm || !domain) return;
  recordForm.recordId.value = String(record.id);
  recordForm.host.value = fqdnToHost(record.fqdn, domain.name);
  recordForm.type.value = record.type;
  recordForm.ttl.value = String(record.ttl);
  recordForm.value.value = record.value;
  recordForm.weight.value = String(record.weight ?? 100);
  recordForm.geoCidrs.value = record.geo_cidrs || "";
  recordForm.healthcheckUrl.value = record.healthcheck_url || "";
  recordForm.enabled.checked = record.enabled === 1;
  if (recordSubmitBtn) recordSubmitBtn.textContent = "Update Record";
  updateRecordTypeHint();
  openRecordModal();
}

async function init() {
  fillDomainSelect(domainSelect);
  fillDomainSelect(ddnsDomainSelect);
  renderRecords();
  renderDdnsTokens();
  resetRecordForm();

  if (domainSelect) {
    domainSelect.addEventListener("change", () => {
      const domainId = Number(domainSelect.value);
      if (domainId > 0) {
        if (ddnsDomainSelect) ddnsDomainSelect.value = String(domainId);
        reloadDomainData(domainId).catch((e) => setMsg(e.message || "failed to load domain data", true));
      }
    });
  }

  if (ddnsDomainSelect) {
    ddnsDomainSelect.addEventListener("change", () => {
      const domainId = Number(ddnsDomainSelect.value);
      if (domainId > 0 && domainSelect) domainSelect.value = String(domainId);
    });
  }

  document.getElementById("refresh-btn")?.addEventListener("click", () => {
    const id = Number(domainSelect?.value || state.selectedDomainId || 0);
    if (id > 0) reloadDomainData(id).catch((e) => setMsg(e.message || "failed to load records", true));
  });

  recordCancelBtn?.addEventListener("click", () => {
    resetRecordForm();
    closeRecordModal();
  });

  openRecordModalBtn?.addEventListener("click", () => {
    resetRecordForm();
    openRecordModal();
  });

  closeRecordModalBtn?.addEventListener("click", () => {
    closeRecordModal();
  });

  document.addEventListener("click", (e) => {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.closest("[data-close-record-modal='1']")) {
      closeRecordModal();
    }
  });

  recordModal?.addEventListener("click", (e) => {
    if (e.target === recordModal) {
      closeRecordModal();
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && recordModal && !recordModal.hidden) {
      closeRecordModal();
    }
  });

  recordTypeSelect?.addEventListener("change", () => {
    updateRecordTypeHint();
  });

  document.querySelectorAll("[data-weight-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (!recordWeightInput) return;
      const val = Number(btn.getAttribute("data-weight-preset") || 100);
      recordWeightInput.value = String(val);
    });
  });

  document.getElementById("create-domain-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const form = new FormData(e.currentTarget);
      const data = await upfetch("/api/domains", { method: "POST", body: { domain: String(form.get("domain") || "") } });
      state.domains.unshift({ id: data.id, name: data.domain, user_id: state.user?.id ?? null, created_at: new Date().toISOString() });
      fillDomainSelect(domainSelect);
      fillDomainSelect(ddnsDomainSelect);
      if (domainSelect) domainSelect.value = String(data.id);
      if (ddnsDomainSelect) ddnsDomainSelect.value = String(data.id);
      await reloadDomainData(data.id);
      setMsg("domain created");
    } catch (err) {
      setMsg(err.message || "failed to create domain", true);
    }
  });

  document.getElementById("create-record-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const form = new FormData(e.currentTarget);
      const domainId = Number(form.get("domainId"));
      const payload = {
        host: String(form.get("host") || "@"),
        type: String(form.get("type") || "A"),
        ttl: Number(form.get("ttl") || 60),
        value: String(form.get("value") || ""),
        weight: Number(form.get("weight") || 100),
        geoCidrs: String(form.get("geoCidrs") || ""),
        healthcheckUrl: String(form.get("healthcheckUrl") || ""),
        enabled: form.get("enabled") !== null,
      };
      const recordId = Number(form.get("recordId") || 0);
      if (recordId > 0) {
        await upfetch("/api/records/" + recordId, { method: "PUT", body: payload });
      } else {
        await upfetch("/api/domains/" + domainId + "/records", { method: "POST", body: payload });
      }
      await reloadRecords(domainId);
      resetRecordForm();
      closeRecordModal();
      setMsg(recordId > 0 ? "record updated" : "record saved");
    } catch (err) {
      setRecordModalMsg(err.message || "failed to save record", true);
      setMsg(err.message || "failed to save record", true);
    }
  });

  document.getElementById("create-ddns-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const form = new FormData(e.currentTarget);
      const domainId = Number(form.get("domainId"));
      const data = await upfetch("/api/domains/" + domainId + "/ddns-tokens", {
        method: "POST",
        body: {
          host: String(form.get("host") || "@"),
          ttl: Number(form.get("ttl") || 60),
        },
      });
      if (tokenOutput) {
        tokenOutput.textContent = JSON.stringify(data, null, 2);
      }
      await reloadDdnsTokens(domainId);
      setMsg("ddns token created");
    } catch (err) {
      setMsg(err.message || "failed to create ddns token", true);
    }
  });

  updateDdnsForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const form = new FormData(e.currentTarget);
      const payload = { token: String(form.get("token") || ""), ip: String(form.get("ip") || "") };
      const data = await upfetch("/api/dyndns/update", { method: "POST", body: payload });
      setMsg("ddns updated: " + JSON.stringify(data));
    } catch (err) {
      setMsg(err.message || "failed to update ddns", true);
    }
  });

  recordsBody?.addEventListener("click", async (e) => {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;
    const action = target.getAttribute("data-record-action");
    const recordId = Number(target.getAttribute("data-record-id") || 0);
    if (!action || recordId <= 0) return;

    if (action === "edit") {
      startRecordEdit(recordId);
      return;
    }
    if (action === "delete") {
      if (!confirm("Delete this record?")) return;
      try {
        await upfetch("/api/records/" + recordId, { method: "DELETE" });
        const id = Number(domainSelect?.value || state.selectedDomainId || 0);
        if (id > 0) await reloadRecords(id);
        setMsg("record deleted");
      } catch (err) {
        setMsg(err.message || "failed to delete record", true);
      }
    }
  });

  ddnsBody?.addEventListener("click", async (e) => {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;
    const action = target.getAttribute("data-token-action");
    if (!action) return;
    const tokenValue = decodeURIComponent(target.getAttribute("data-token-value") || "");
    if (action === "use") {
      if (updateDdnsForm) updateDdnsForm.token.value = tokenValue;
      setMsg("token populated in DDNS update form");
      return;
    }
    if (action === "copy") {
      if (!tokenValue) return setMsg("token unavailable for this entry", true);
      try {
        await navigator.clipboard.writeText(tokenValue);
        setMsg("token copied");
      } catch {
        setMsg("clipboard copy failed", true);
      }
      return;
    }
    if (action === "delete") {
      const tokenId = Number(target.getAttribute("data-token-id") || 0);
      if (tokenId <= 0) return;
      if (!confirm("Delete this DDNS token?")) return;
      try {
        await upfetch("/api/ddns-tokens/" + tokenId, { method: "DELETE" });
        const domainId = Number(ddnsDomainSelect?.value || state.selectedDomainId || 0);
        if (domainId > 0) await reloadDdnsTokens(domainId);
        setMsg("token deleted");
      } catch (err) {
        setMsg(err.message || "failed to delete token", true);
      }
    }
  });
}

init().catch((e) => setMsg(e.message || "failed to init", true));
updateRecordTypeHint();
`;
}

function updateDynamicDns(ddns: DdnsTokenRow, ip: string, userAgent: string) {
  const current = findRecordValueStmt.get(ddns.domain_id, ddns.fqdn);
  deleteRecordsByNameTypeStmt.run(ddns.domain_id, ddns.fqdn, "A");
  insertRecordStmt.run(ddns.domain_id, ddns.fqdn, "A", ddns.ttl, ip, 100, "", 1, null);
  insertDdnsUpdateStmt.run(ddns.id, ip, current?.value ?? null, ip, userAgent);
  return { previous: current?.value ?? null, changed: current?.value !== ip };
}

function ensureDefaultAuthorityRecords(domainId: number, domainName: string) {
  const zoneFqdn = normalizeFqdn(domainName);
  const nsFqdn = hostToFqdn(DEFAULT_NS_HOST, domainName);
  const soaValue = `${nsFqdn} hostmaster.${zoneFqdn} ${Number(
    new Date().toISOString().slice(0, 10).replaceAll("-", ""),
  )}01 3600 900 1209600 300`;
  insertRecordIfMissingStmt.run(domainId, zoneFqdn, "NS", 300, nsFqdn);
  insertRecordIfMissingStmt.run(domainId, zoneFqdn, "SOA", 300, soaValue);
  insertRecordIfMissingStmt.run(domainId, nsFqdn, "A", 300, DEFAULT_NS_IP);
}

export function startApiServer() {
  const appDomainsForUserStmt = db.query<DomainRow, [number]>(
    `SELECT id, user_id, name, created_at FROM domains WHERE user_id = ?1 ORDER BY id DESC`,
  );
  const appRecordsByDomainStmt = db.query<RecordRow, [number]>(
    `
      SELECT
        id, domain_id, fqdn, type, ttl, value, weight, geo_cidrs, enabled, healthcheck_url, healthy,
        last_health_check_at, last_health_error, created_at, updated_at
      FROM records
      WHERE domain_id = ?1
      ORDER BY id DESC
    `,
  );
  const appDdnsTokensByDomainStmt = db.query<DdnsTokenRow, [number, number]>(
    `
      SELECT t.id, t.user_id, t.domain_id, t.fqdn, t.token_value, t.ttl, t.enabled, t.created_at
      FROM ddns_tokens t
      JOIN domains d ON d.id = t.domain_id
      WHERE t.domain_id = ?1 AND d.user_id = ?2
      ORDER BY t.id DESC
    `,
  );

  Bun.serve({
    hostname: API_HOST,
    port: API_PORT,
    routes: {
      "/health": () => json({ ok: true }),
      "/app": (req) => {
        const token = getSessionToken(req);
        const user = getSessionUserByToken(token);
        const domains = user ? appDomainsForUserStmt.all(user.id) : [];
        const selectedDomainId = domains[0]?.id ?? null;
        const records =
          user && selectedDomainId !== null ? appRecordsByDomainStmt.all(selectedDomainId) : [];
        const ddnsTokens =
          user && selectedDomainId !== null
            ? appDdnsTokensByDomainStmt.all(selectedDomainId, user.id)
            : [];
        return new Response(
          appHtml({
            user,
            token: user ? token : "",
            domains,
            records,
            ddnsTokens,
            selectedDomainId,
          }),
          { headers: { "content-type": "text/html; charset=utf-8" } },
        );
      },
      "/app/client.js": () =>
        new Response(appClientJs(), {
          headers: { "content-type": "application/javascript; charset=utf-8" },
        }),
      "/app/register": {
        POST: async (req) => {
          const form = await req.formData();
          const email = String(form.get("email") ?? "").trim().toLowerCase();
          const password = String(form.get("password") ?? "").trim();
          if (!email || password.length < 8) return redirect("/app");
          if (findUserByEmailStmt.get(email)) return redirect("/app");
          const hash = await Bun.password.hash(password);
          const result = insertUserStmt.run(email, hash);
          const userId = Number(result.lastInsertRowid);
          const token = randomToken("api");
          insertApiTokenStmt.run(userId, tokenHash(token), "web-register");
          return redirect("/app", { "set-cookie": setTokenCookie(token) });
        },
      },
      "/app/login": {
        POST: async (req) => {
          const form = await req.formData();
          const email = String(form.get("email") ?? "").trim().toLowerCase();
          const password = String(form.get("password") ?? "").trim();
          const user = findUserByEmailStmt.get(email);
          if (!user) return redirect("/app");
          const ok = await Bun.password.verify(password, user.password_hash);
          if (!ok) return redirect("/app");
          const token = randomToken("api");
          insertApiTokenStmt.run(user.id, tokenHash(token), "web-login");
          return redirect("/app", { "set-cookie": setTokenCookie(token) });
        },
      },
      "/app/logout": {
        POST: () => redirect("/app", { "set-cookie": clearTokenCookie() }),
      },
      "/openapi.json": (req) => json(buildOpenApiSpec(serverUrlFor(req))),
      "/docs": () =>
        new Response(scalarHtml("/openapi.json"), {
          headers: { "content-type": "text/html; charset=utf-8" },
        }),
      "/scalar": () =>
        new Response(scalarHtml("/openapi.json"), {
          headers: { "content-type": "text/html; charset=utf-8" },
        }),
      "/scaler": () =>
        new Response(scalarHtml("/openapi.json"), {
          headers: { "content-type": "text/html; charset=utf-8" },
        }),

      "/api/register": {
        POST: async (req) => {
          const body = await readBody<{ email?: string; password?: string }>(req);
          const email = body?.email?.trim().toLowerCase();
          const password = body?.password?.trim();
          if (!email || !password || password.length < 8) {
            return invalid("email and password(min 8 chars) are required");
          }

          const existing = findUserByEmailStmt.get(email);
          if (existing) return invalid("email already exists", 409);

          const passwordHash = await Bun.password.hash(password);
          const result = insertUserStmt.run(email, passwordHash);
          const userId = Number(result.lastInsertRowid);
          const token = randomToken("api");
          insertApiTokenStmt.run(userId, tokenHash(token), "register");
          return json({ token, user: { id: userId, email } }, { status: 201 });
        },
      },

      "/api/login": {
        POST: async (req) => {
          const body = await readBody<{ email?: string; password?: string }>(req);
          const email = body?.email?.trim().toLowerCase();
          const password = body?.password?.trim();
          if (!email || !password) {
            return invalid("email and password are required");
          }

          const user = findUserByEmailStmt.get(email);
          if (!user) return invalid("invalid credentials", 401);
          const ok = await Bun.password.verify(password, user.password_hash);
          if (!ok) return invalid("invalid credentials", 401);

          const token = randomToken("api");
          insertApiTokenStmt.run(user.id, tokenHash(token), "login");
          return json({ token, user: { id: user.id, email: user.email } });
        },
      },

      "/api/domains": {
        GET: async (req) => {
          const user = await authenticate(req);
          if (!user) return invalid("unauthorized", 401);
          return json({ domains: listDomainsStmt.all(user.id) });
        },
        POST: async (req) => {
          const user = await authenticate(req);
          if (!user) return invalid("unauthorized", 401);
          const body = await readBody<{ domain?: string }>(req);
          if (!body?.domain) return invalid("domain is required");

          try {
            const domain = normalizeDomain(body.domain);
            const result = createDomainStmt.run(user.id, domain);
            const domainId = Number(result.lastInsertRowid);
            ensureDefaultAuthorityRecords(domainId, domain);
            return json(
              { id: domainId, domain, userId: user.id },
              { status: 201 },
            );
          } catch (error) {
            return invalid(
              error instanceof Error ? error.message : "failed to create domain",
              400,
            );
          }
        },
      },

      "/api/domains/:domainId/records": {
        GET: async (req) => {
          const user = await authenticate(req);
          if (!user) return invalid("unauthorized", 401);

          const domainId = Number(req.params.domainId);
          if (!Number.isInteger(domainId) || domainId <= 0) return invalid("invalid domain id");
          const domain = getDomainStmt.get(domainId, user.id);
          if (!domain) return invalid("domain not found", 404);
          return json({ records: listRecordsStmt.all(domainId) });
        },
        POST: async (req) => {
          const user = await authenticate(req);
          if (!user) return invalid("unauthorized", 401);

          const domainId = Number(req.params.domainId);
          if (!Number.isInteger(domainId) || domainId <= 0) return invalid("invalid domain id");
          const domain = getDomainStmt.get(domainId, user.id);
          if (!domain) return invalid("domain not found", 404);

          const body = await readBody<{
            host?: string;
            type?: "A" | "AAAA" | "CNAME" | "NS" | "SOA" | "MX" | "TXT" | "CAA" | "SRV" | "PTR";
            ttl?: number;
            value?: string;
            weight?: number;
            geoCidrs?: string;
            enabled?: boolean;
            healthcheckUrl?: string;
          }>(req);

          const host = body?.host ?? "@";
          const type = body?.type;
          const ttl = Number(body?.ttl ?? 60);
          const value = body?.value;
          if (!type || !value) return invalid("type and value are required");
          if (!Number.isInteger(ttl) || ttl <= 0 || ttl > 86400) return invalid("invalid ttl");

          try {
            const fqdn = hostToFqdn(host, domain.name);
            const normalizedValue = normalizeRecordValue(type, value);
            const routing = normalizeRoutingOptions({
              weight: body?.weight,
              geoCidrs: body?.geoCidrs,
              enabled: body?.enabled,
              healthcheckUrl: body?.healthcheckUrl,
            });
            insertRecordStmt.run(
              domainId,
              fqdn,
              type,
              ttl,
              normalizedValue,
              routing.weight,
              routing.geoCidrs,
              routing.enabled,
              routing.healthcheckUrl,
            );
            return json(
              {
                ok: true,
                fqdn,
                type,
                ttl,
                value: normalizedValue,
                weight: routing.weight,
                geoCidrs: routing.geoCidrs,
                enabled: Boolean(routing.enabled),
                healthcheckUrl: routing.healthcheckUrl,
              },
              { status: 201 },
            );
          } catch (error) {
            return invalid(error instanceof Error ? error.message : "failed to create record");
          }
        },
      },

      "/api/records/:recordId": {
        PUT: async (req) => {
          const user = await authenticate(req);
          if (!user) return invalid("unauthorized", 401);
          const recordId = Number(req.params.recordId);
          if (!Number.isInteger(recordId) || recordId <= 0) return invalid("invalid record id");

          const record = getRecordForOwnerStmt.get(recordId, user.id);
          if (!record) return invalid("record not found", 404);
          const domain = db
            .query<DomainRow, [number]>(`SELECT id, user_id, name, created_at FROM domains WHERE id = ?1`)
            .get(record.domain_id ?? -1);
          if (!domain) return invalid("domain not found", 404);

          const body = await readBody<{
            host?: string;
            type?: "A" | "AAAA" | "CNAME" | "NS" | "SOA" | "MX" | "TXT" | "CAA" | "SRV" | "PTR";
            ttl?: number;
            value?: string;
            weight?: number;
            geoCidrs?: string;
            enabled?: boolean;
            healthcheckUrl?: string;
          }>(req);
          const host = body?.host ?? "@";
          const type = body?.type ?? record.type;
          const ttl = Number(body?.ttl ?? record.ttl);
          const value = body?.value ?? record.value;
          if (!Number.isInteger(ttl) || ttl <= 0 || ttl > 86400) return invalid("invalid ttl");

          try {
            const fqdn = hostToFqdn(host, domain.name);
            const normalizedValue = normalizeRecordValue(type, value);
            const routing = normalizeRoutingOptions({
              weight: body?.weight ?? record.weight,
              geoCidrs: body?.geoCidrs ?? record.geo_cidrs,
              enabled: body?.enabled ?? (record.enabled === 1),
              healthcheckUrl: body?.healthcheckUrl ?? record.healthcheck_url ?? "",
            });
            updateRecordStmt.run(
              recordId,
              domain.id,
              fqdn,
              type,
              ttl,
              normalizedValue,
              routing.weight,
              routing.geoCidrs,
              routing.enabled,
              routing.healthcheckUrl,
            );
            return json({
              ok: true,
              id: recordId,
              fqdn,
              type,
              ttl,
              value: normalizedValue,
              weight: routing.weight,
              geoCidrs: routing.geoCidrs,
              enabled: Boolean(routing.enabled),
              healthcheckUrl: routing.healthcheckUrl,
            });
          } catch (error) {
            return invalid(error instanceof Error ? error.message : "failed to update record");
          }
        },
        DELETE: async (req) => {
          const user = await authenticate(req);
          if (!user) return invalid("unauthorized", 401);
          const recordId = Number(req.params.recordId);
          if (!Number.isInteger(recordId) || recordId <= 0) return invalid("invalid record id");
          const record = getRecordForOwnerStmt.get(recordId, user.id);
          if (!record) return invalid("record not found", 404);
          deleteRecordStmt.run(recordId);
          return json({ ok: true, id: recordId });
        },
      },

      "/api/domains/:domainId/ddns-tokens": {
        GET: async (req) => {
          const user = await authenticate(req);
          if (!user) return invalid("unauthorized", 401);
          const domainId = Number(req.params.domainId);
          if (!Number.isInteger(domainId) || domainId <= 0) return invalid("invalid domain id");
          const domain = getDomainStmt.get(domainId, user.id);
          if (!domain) return invalid("domain not found", 404);
          return json({ tokens: listDdnsTokensForDomainStmt.all(domainId, user.id) });
        },
        POST: async (req) => {
          const user = await authenticate(req);
          if (!user) return invalid("unauthorized", 401);
          const domainId = Number(req.params.domainId);
          if (!Number.isInteger(domainId) || domainId <= 0) return invalid("invalid domain id");
          const domain = getDomainStmt.get(domainId, user.id);
          if (!domain) return invalid("domain not found", 404);

          const body = await readBody<{ host?: string; ttl?: number }>(req);
          const host = body?.host ?? "@";
          const ttl = Number(body?.ttl ?? 60);
          if (!Number.isInteger(ttl) || ttl <= 0 || ttl > 86400) return invalid("invalid ttl");

          try {
            const fqdn = hostToFqdn(host, domain.name);
            const token = randomToken("ddns");
            createDdnsTokenStmt.run(user.id, domainId, fqdn, token, tokenHash(token), ttl);
            return json({ token, fqdn, ttl }, { status: 201 });
          } catch (error) {
            return invalid(error instanceof Error ? error.message : "failed to create ddns token");
          }
        },
      },
      "/api/ddns-tokens/:tokenId": {
        DELETE: async (req) => {
          const user = await authenticate(req);
          if (!user) return invalid("unauthorized", 401);
          const tokenId = Number(req.params.tokenId);
          if (!Number.isInteger(tokenId) || tokenId <= 0) return invalid("invalid token id");
          const token = getDdnsTokenForOwnerStmt.get(tokenId, user.id);
          if (!token) return invalid("token not found", 404);
          deleteDdnsTokenStmt.run(tokenId);
          return json({ ok: true, id: tokenId });
        },
      },

      "/api/dyndns/update": {
        POST: async (req) => {
          const body = await readBody<{ token?: string; ip?: string }>(req);
          const token = body?.token?.trim();
          if (!token) return invalid("token is required");

          const ddns = findDdnsTokenStmt.get(tokenHash(token));
          if (!ddns || ddns.enabled !== 1) return invalid("invalid token", 401);

          const ip = (body?.ip?.trim() ?? getClientIp(req)).trim();
          if (!ip || isIP(ip) !== 4) return invalid("valid IPv4 ip is required");

          const result = updateDynamicDns(ddns, ip, req.headers.get("user-agent") ?? "unknown");

          return json({
            ok: true,
            fqdn: ddns.fqdn,
            type: "A",
            ip,
            changed: result.changed,
          });
        },
      },
      "/nic/update": {
        GET: (req) => {
          const token = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "").trim() ?? "";
          if (!token) return new Response("badauth", { status: 401 });
          const ddns = findDdnsTokenStmt.get(tokenHash(token));
          if (!ddns || ddns.enabled !== 1) return new Response("badauth", { status: 401 });

          const url = new URL(req.url);
          const ip = (url.searchParams.get("myip")?.trim() ?? getClientIp(req)).trim();
          if (!ip || isIP(ip) !== 4) return new Response("dnserr", { status: 400 });

          const result = updateDynamicDns(ddns, ip, req.headers.get("user-agent") ?? "unknown");
          const prefix = result.changed ? "good" : "nochg";
          return new Response(`${prefix} ${ip}\n`, { status: 200 });
        },
      },
    },
    fetch() {
      return json({ error: "not found" }, { status: 404 });
    },
  });

  console.log(`API server listening on http://${API_HOST}:${API_PORT}`);
  console.log(`Using SQLite database at ${DB_PATH}`);
}
