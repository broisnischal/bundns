# Bun DNS + API + Dynamic DNS

High-performance Bun services backed by `bun:sqlite`:

- UDP DNS resolver/server (`src/index.ts`)
- HTTP API service (`src/api-index.ts`) for:
  - user register/login
  - domain and record management
  - Dynamic DNS token creation + updates

Both services share one SQLite database file.

## Install

```bash
bun install
```

## Run locally

Run DNS:

```bash
bun run dev:dns
```

Run API (different terminal):

```bash
bun run dev:api
```

Open visual dashboard (SSR + up-fetch integration):

```bash
http://127.0.0.1:3000/app
```

This dashboard is Bun-native SSR (no Vite), and uses `up-fetch` in the browser module for API integration.

## Build and compile

Build JS bundles:

```bash
bun run build
```

Compile native executables:

```bash
bun run compile
```

Outputs:

- `./bin/dns-server`
- `./bin/api-server`

## Environment variables

Shared:

- `DNS_DB_PATH` (default `./data/dns.sqlite`)

DNS server:

- `DNS_HOST` (default `0.0.0.0`)
- `DNS_PORT` (default `5353`)
- `DNS_CACHE_TTL_SECONDS` (default `5`, set `0` to disable cache)

API server:

- `API_HOST` (default `0.0.0.0`)
- `API_PORT` (default `3000`)

## API quickstart

OpenAPI JSON:

```bash
curl -sS http://127.0.0.1:3000/openapi.json
```

Scalar docs UI:

```bash
open http://127.0.0.1:3000/docs
```

Register:

```bash
curl -sS http://127.0.0.1:3000/api/register \
  -H "content-type: application/json" \
  -d '{"email":"you@example.com","password":"supersecret123"}'
```

Login:

```bash
curl -sS http://127.0.0.1:3000/api/login \
  -H "content-type: application/json" \
  -d '{"email":"you@example.com","password":"supersecret123"}'
```

Create domain:

```bash
curl -sS http://127.0.0.1:3000/api/domains \
  -H "authorization: Bearer <API_TOKEN>" \
  -H "content-type: application/json" \
  -d '{"domain":"mydomain.com"}'
```

Create A record:

```bash
curl -sS http://127.0.0.1:3000/api/domains/<DOMAIN_ID>/records \
  -H "authorization: Bearer <API_TOKEN>" \
  -H "content-type: application/json" \
  -d '{"host":"home","type":"A","ttl":60,"value":"1.2.3.4"}'
```

Create DDNS token:

```bash
curl -sS http://127.0.0.1:3000/api/domains/<DOMAIN_ID>/ddns-tokens \
  -H "authorization: Bearer <API_TOKEN>" \
  -H "content-type: application/json" \
  -d '{"host":"home","ttl":60}'
```

Update DDNS:

```bash
curl -sS http://127.0.0.1:3000/api/dyndns/update \
  -H "content-type: application/json" \
  -d '{"token":"<DDNS_TOKEN>","ip":"5.6.7.8"}'
```

Then resolve via DNS service:

```bash
dig @127.0.0.1 -p 5353 home.mydomain.com A +short
```

## Docker

Build DNS image:

```bash
docker build -f Dockerfile.dns -t bun-dns:local .
```

Build API image:

```bash
docker build -f Dockerfile.api -t bun-dns-api:local .
```

Or run both with compose:

```bash
docker compose up --build -d
```

## Performance notes

- Uses prepared statements + SQLite WAL mode.
- DNS reads use in-memory cache (`DNS_CACHE_TTL_SECONDS`).
- Keep DB on local SSD and avoid networked filesystems for best latency.
