import { HOST, PORT, RCODE, DB_PATH } from "./constants";
import {
  buildErrorResponse,
  buildSuccessResponse,
  isSupportedClass,
  parseQuery,
} from "./dns-codec";
import { DnsRepository } from "./repository";

export function startServer() {
  const repository = new DnsRepository(DB_PATH);

  const server = Bun.udpSocket({
    hostname: HOST,
    port: PORT,
    socket: {
      data(socket, data, port, address) {
        const query = new Uint8Array(data);
        const context = parseQuery(query);
        if (!context) return;

        if (!isSupportedClass(context.qclass)) {
          const response = buildErrorResponse(context.id, RCODE.NOTIMP);
          socket.send(response, port, address);
          return;
        }

        try {
          const lookup = repository.lookup(context.qname);
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
