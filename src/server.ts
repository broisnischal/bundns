import {
  HOST,
  PORT,
  RCODE,
  DB_PATH,
  DNS_RATE_LIMIT_BURST,
  DNS_RATE_LIMIT_QPS,
  DNS_RATE_LIMIT_BLOCK_SECONDS,
} from "./constants";
import {
  buildErrorResponse,
  buildSuccessResponse,
  isSupportedClass,
  parseQuery,
} from "./dns-codec";
import { DnsRepository } from "./repository";

export function startServer() {
  const repository = new DnsRepository(DB_PATH);
  const limiter = new Map<string, { tokens: number; last: number; blockedUntil: number }>();

  function rateLimitKey(address: string) {
    return address || "unknown";
  }

  function isAllowed(address: string) {
    const key = rateLimitKey(address);
    const now = Date.now();
    const state = limiter.get(key) ?? {
      tokens: Math.max(1, DNS_RATE_LIMIT_BURST),
      last: now,
      blockedUntil: 0,
    };
    if (now < state.blockedUntil) {
      limiter.set(key, state);
      return false;
    }

    const elapsed = Math.max(0, now - state.last) / 1000;
    state.tokens = Math.min(
      Math.max(1, DNS_RATE_LIMIT_BURST),
      state.tokens + elapsed * Math.max(1, DNS_RATE_LIMIT_QPS),
    );
    state.last = now;
    if (state.tokens < 1) {
      state.blockedUntil = now + Math.max(1, DNS_RATE_LIMIT_BLOCK_SECONDS) * 1000;
      limiter.set(key, state);
      return false;
    }
    state.tokens -= 1;
    limiter.set(key, state);
    return true;
  }

  const server = Bun.udpSocket({
    hostname: HOST,
    port: PORT,
    socket: {
      data(socket, data, port, address) {
        const query = new Uint8Array(data);
        const context = parseQuery(query);
        if (!context) return;

        if (!isAllowed(address)) {
          const response = buildErrorResponse(context.id, RCODE.REFUSED);
          socket.send(response, port, address);
          return;
        }

        if (!isSupportedClass(context.qclass)) {
          const response = buildErrorResponse(context.id, RCODE.NOTIMP);
          socket.send(response, port, address);
          return;
        }

        try {
          const lookup = repository.lookup(context.qname, context.qtype, address);
          const response = buildSuccessResponse(
            context,
            lookup.records,
            lookup.authorityRecords,
            Boolean(lookup.zoneName),
            lookup.zoneName,
          );
          socket.send(response, port, address);
        } catch (error) {
          console.error("Response build failed:", error);
          const response = buildErrorResponse(context.id, RCODE.SERVFAIL);
          socket.send(response, port, address);
        }
      },
      error(_socket, error) {
        console.error("UDP socket error:", error);
      },
    },
  });

  console.log(`DNS server listening on udp://${HOST}:${PORT}`);
  console.log(`Using SQLite database at ${DB_PATH}`);
  console.log("Try: dig @127.0.0.1 -p 5353 example.local A");

  const shutdown = () => {
    console.log("\nShutting down DNS server...");
    try {
      repository.close();
    } catch (error) {
      console.error("Failed to close repository:", error);
    }
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
