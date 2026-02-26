import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { up } from "up-fetch";
import { openDatabase, hostToFqdn, normalizeDomain, normalizeFqdn } from "./db";
import { buildOpenApiSpec, scalarHtml } from "./openapi";

const API_HOST = process.env.API_HOST ?? "0.0.0.0";
const API_PORT = Number(process.env.API_PORT ?? 3000);
const DB_PATH = process.env.DNS_DB_PATH ?? "./data/dns.sqlite";

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
  created_at: string;
  updated_at: string;
};
type DdnsTokenRow = {
  id: number;
  user_id: number;
  domain_id: number;
  fqdn: string;
  ttl: number;
  enabled: number;
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
const insertRecordStmt = db.query<{ lastInsertRowid: number }, [number, string, string, number, string]>(
  `
    INSERT INTO records (domain_id, fqdn, type, ttl, value)
    VALUES (?1, ?2, ?3, ?4, ?5)
    ON CONFLICT (domain_id, fqdn, type, value)
    DO UPDATE SET value = excluded.value, ttl = excluded.ttl, updated_at = CURRENT_TIMESTAMP
  `,
);
const listRecordsStmt = db.query<RecordRow, [number]>(
  `
    SELECT id, domain_id, fqdn, type, ttl, value, created_at, updated_at
    FROM records
    WHERE domain_id = ?1
    ORDER BY id DESC
  `,
);
const getRecordForOwnerStmt = db.query<RecordRow, [number, number]>(
  `
    SELECT r.id, r.domain_id, r.fqdn, r.type, r.ttl, r.value, r.created_at, r.updated_at
    FROM records r
    JOIN domains d ON d.id = r.domain_id
    WHERE r.id = ?1 AND d.user_id = ?2
    LIMIT 1
  `,
);
const updateRecordStmt = db.query<{ changes: number }, [number, number, string, string, number, string]>(
  `
    UPDATE records
    SET fqdn = ?3, type = ?4, ttl = ?5, value = ?6, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?1 AND domain_id = ?2
  `,
);
const deleteRecordStmt = db.query<{ changes: number }, [number]>(`DELETE FROM records WHERE id = ?1`);
const createDdnsTokenStmt = db.query<{ lastInsertRowid: number }, [number, number, string, string, number]>(
  `
    INSERT INTO ddns_tokens (user_id, domain_id, fqdn, token_hash, ttl)
    VALUES (?1, ?2, ?3, ?4, ?5)
  `,
);
const findDdnsTokenStmt = db.query<DdnsTokenRow, [string]>(
  `
    SELECT id, user_id, domain_id, fqdn, ttl, enabled
    FROM ddns_tokens
    WHERE token_hash = ?1
    LIMIT 1
  `,
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
    return `${normalizeFqdn(parts[0])} ${normalizeFqdn(parts[1])} ${numbers.join(" ")}`;
  }
  if (type === "MX") {
    const parts = trimmed.split(/\s+/);
    if (parts.length !== 2) throw new Error("MX must be: preference exchange");
    const preference = Number(parts[0]);
    if (!Number.isInteger(preference) || preference < 0 || preference > 65535) {
      throw new Error("Invalid MX preference");
    }
    return `${preference} ${normalizeFqdn(parts[1])}`;
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
    const [priority, weight, port] = parts.slice(0, 3).map((part) => Number(part));
    if (
      [priority, weight, port].some(
        (v) => !Number.isInteger(v) || v < 0 || v > 65535,
      )
    ) {
      throw new Error("Invalid SRV numeric fields");
    }
    return `${priority} ${weight} ${port} ${normalizeFqdn(parts[3])}`;
  }
  throw new Error("Unsupported record type");
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
  selectedDomainId: number | null;
}) {
  const initial = safeJson({
    user: state.user,
    token: state.token,
    domains: state.domains,
    records: state.records,
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
      body { font-family: system-ui, sans-serif; max-width: 1120px; margin: 1.5rem auto; padding: 0 1rem; }
      .row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; }
      .card { border: 1px solid #ddd; border-radius: 12px; padding: 1rem; }
      input, select, button { padding: .55rem .7rem; margin: .25rem 0; width: 100%; box-sizing: border-box; }
      table { width: 100%; border-collapse: collapse; }
      th, td { border-bottom: 1px solid #eee; text-align: left; padding: .45rem; font-size: .93rem; }
      code, pre { background: #111; color: #eee; border-radius: 8px; padding: .2rem .35rem; }
      #msg { min-height: 1.2rem; color: #0a7c25; }
    </style>
  </head>
  <body>
    <div class="row">
      <div>
        <h1>DNS Control Panel</h1>
        <div>Logged in as <strong>${state.user.email}</strong></div>
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
        <h3>Create/Upsert Record</h3>
        <form id="create-record-form">
          <select name="domainId" id="domain-select"></select>
          <input name="host" placeholder="@" value="@" />
          <select name="type">
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
          <input name="ttl" type="number" value="60" min="1" max="86400" />
          <input name="value" placeholder="1.2.3.4 or target.domain." required />
          <button type="submit">Save Record</button>
        </form>
      </div>

      <div class="card">
        <h3>Create DDNS Token</h3>
        <form id="create-ddns-form">
          <select name="domainId" id="ddns-domain-select"></select>
          <input name="host" placeholder="home" />
          <input name="ttl" type="number" value="60" min="1" max="86400" />
          <button type="submit">Create Token</button>
        </form>
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
      <div class="row">
        <h3>Records</h3>
        <button id="refresh-btn" type="button">Refresh</button>
      </div>
      <table>
        <thead><tr><th>ID</th><th>FQDN</th><th>TYPE</th><th>TTL</th><th>VALUE</th></tr></thead>
        <tbody id="records-body"></tbody>
      </table>
    </div>

    <script>window.__APP_STATE__ = ${initial};</script>
    <script type="module" src="/app/client.js"></script>
  </body>
</html>`;
}

function appClientJs() {
  return `import { up } from "https://esm.sh/up-fetch@2.5.1";

const state = window.__APP_STATE__ ?? { user: null, token: "", domains: [], records: [], selectedDomainId: null };
const msg = document.getElementById("msg");
const recordsBody = document.getElementById("records-body");
const domainSelect = document.getElementById("domain-select");
const ddnsDomainSelect = document.getElementById("ddns-domain-select");
const tokenOutput = document.getElementById("ddns-token-output");

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

function renderRecords() {
  if (!recordsBody) return;
  recordsBody.innerHTML = "";
  for (const r of state.records) {
    const tr = document.createElement("tr");
    tr.innerHTML = "<td>" + r.id + "</td><td>" + r.fqdn + "</td><td>" + r.type + "</td><td>" + r.ttl + "</td><td>" + r.value + "</td>";
    recordsBody.appendChild(tr);
  }
}

async function reloadRecords(domainId) {
  const data = await upfetch("/api/domains/" + domainId + "/records");
  state.records = data.records ?? [];
  state.selectedDomainId = domainId;
  renderRecords();
}

async function init() {
  fillDomainSelect(domainSelect);
  fillDomainSelect(ddnsDomainSelect);
  renderRecords();

  if (domainSelect) {
    domainSelect.addEventListener("change", () => {
      const domainId = Number(domainSelect.value);
      if (domainId > 0) {
        reloadRecords(domainId).catch((e) => setMsg(e.message || "failed to load records", true));
      }
    });
  }

  document.getElementById("refresh-btn")?.addEventListener("click", () => {
    const id = Number(domainSelect?.value || state.selectedDomainId || 0);
    if (id > 0) reloadRecords(id).catch((e) => setMsg(e.message || "failed to load records", true));
  });

  document.getElementById("create-domain-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const form = new FormData(e.currentTarget);
      const data = await upfetch("/api/domains", { method: "POST", body: { domain: String(form.get("domain") || "") } });
      state.domains.unshift({ id: data.id, name: data.domain, user_id: state.user?.id ?? null, created_at: new Date().toISOString() });
      fillDomainSelect(domainSelect);
      fillDomainSelect(ddnsDomainSelect);
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
      await upfetch("/api/domains/" + domainId + "/records", {
        method: "POST",
        body: {
          host: String(form.get("host") || "@"),
          type: String(form.get("type") || "A"),
          ttl: Number(form.get("ttl") || 60),
          value: String(form.get("value") || ""),
        },
      });
      await reloadRecords(domainId);
      setMsg("record saved");
    } catch (err) {
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
      setMsg("ddns token created");
    } catch (err) {
      setMsg(err.message || "failed to create ddns token", true);
    }
  });

  document.getElementById("update-ddns-form")?.addEventListener("submit", async (e) => {
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
}

init().catch((e) => setMsg(e.message || "failed to init", true));
`;
}

function updateDynamicDns(ddns: DdnsTokenRow, ip: string, userAgent: string) {
  const current = findRecordValueStmt.get(ddns.domain_id, ddns.fqdn);
  deleteRecordsByNameTypeStmt.run(ddns.domain_id, ddns.fqdn, "A");
  insertRecordStmt.run(ddns.domain_id, ddns.fqdn, "A", ddns.ttl, ip);
  insertDdnsUpdateStmt.run(ddns.id, ip, current?.value ?? null, ip, userAgent);
  return { previous: current?.value ?? null, changed: current?.value !== ip };
}

export function startApiServer() {
  const appDomainsForUserStmt = db.query<DomainRow, [number]>(
    `SELECT id, user_id, name, created_at FROM domains WHERE user_id = ?1 ORDER BY id DESC`,
  );
  const appRecordsByDomainStmt = db.query<RecordRow, [number]>(
    `
      SELECT id, domain_id, fqdn, type, ttl, value, created_at, updated_at
      FROM records
      WHERE domain_id = ?1
      ORDER BY id DESC
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
        return new Response(
          appHtml({
            user,
            token: user ? token : "",
            domains,
            records,
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
            return json(
              { id: Number(result.lastInsertRowid), domain, userId: user.id },
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
            insertRecordStmt.run(domainId, fqdn, type, ttl, normalizedValue);
            return json({ ok: true, fqdn, type, ttl, value: normalizedValue }, { status: 201 });
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
          }>(req);
          const host = body?.host ?? "@";
          const type = body?.type ?? record.type;
          const ttl = Number(body?.ttl ?? record.ttl);
          const value = body?.value ?? record.value;
          if (!Number.isInteger(ttl) || ttl <= 0 || ttl > 86400) return invalid("invalid ttl");

          try {
            const fqdn = hostToFqdn(host, domain.name);
            const normalizedValue = normalizeRecordValue(type, value);
            updateRecordStmt.run(recordId, domain.id, fqdn, type, ttl, normalizedValue);
            return json({ ok: true, id: recordId, fqdn, type, ttl, value: normalizedValue });
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
            createDdnsTokenStmt.run(user.id, domainId, fqdn, tokenHash(token), ttl);
            return json({ token, fqdn, ttl }, { status: 201 });
          } catch (error) {
            return invalid(error instanceof Error ? error.message : "failed to create ddns token");
          }
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
