export function buildOpenApiSpec(serverUrl: string) {
  return {
    openapi: "3.1.0",
    info: {
      title: "Bun DNS API",
      version: "1.0.0",
      description:
        "Manage domains, DNS records, and Dynamic DNS tokens for the Bun DNS server.",
    },
    servers: [{ url: serverUrl }],
    tags: [
      { name: "Health" },
      { name: "Auth" },
      { name: "Domains" },
      { name: "Records" },
      { name: "Dynamic DNS" },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "API token",
        },
      },
      schemas: {
        ErrorResponse: {
          type: "object",
          properties: {
            error: { type: "string" },
          },
          required: ["error"],
        },
      },
    },
    paths: {
      "/health": {
        get: {
          tags: ["Health"],
          summary: "Health check",
          responses: {
            "200": { description: "OK" },
          },
        },
      },
      "/api/register": {
        post: {
          tags: ["Auth"],
          summary: "Register user",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    email: { type: "string", format: "email" },
                    password: { type: "string", minLength: 8 },
                  },
                  required: ["email", "password"],
                },
              },
            },
          },
          responses: {
            "201": { description: "User registered with API token" },
            "400": { description: "Bad request" },
            "409": { description: "Email already exists" },
          },
        },
      },
      "/api/login": {
        post: {
          tags: ["Auth"],
          summary: "Login and issue API token",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    email: { type: "string", format: "email" },
                    password: { type: "string" },
                  },
                  required: ["email", "password"],
                },
              },
            },
          },
          responses: {
            "200": { description: "Login success with API token" },
            "401": { description: "Invalid credentials" },
          },
        },
      },
      "/api/domains": {
        get: {
          tags: ["Domains"],
          summary: "List domains for authenticated user",
          security: [{ bearerAuth: [] }],
          responses: {
            "200": { description: "Domains list" },
            "401": { description: "Unauthorized" },
          },
        },
        post: {
          tags: ["Domains"],
          summary: "Create domain",
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    domain: { type: "string", example: "example.com" },
                  },
                  required: ["domain"],
                },
              },
            },
          },
          responses: {
            "201": { description: "Domain created" },
            "400": { description: "Invalid domain" },
            "401": { description: "Unauthorized" },
          },
        },
      },
      "/api/domains/{domainId}/records": {
        get: {
          tags: ["Records"],
          summary: "List records for a domain",
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: "domainId",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
          ],
          responses: {
            "200": { description: "Records list" },
            "401": { description: "Unauthorized" },
            "404": { description: "Domain not found" },
          },
        },
        post: {
          tags: ["Records"],
          summary: "Create or upsert a DNS record",
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: "domainId",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
          ],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    host: { type: "string", example: "home" },
                    type: {
                      type: "string",
                      enum: ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "SRV", "PTR"],
                    },
                    ttl: { type: "integer", minimum: 1, maximum: 86400 },
                    value: { type: "string" },
                    weight: {
                      type: "integer",
                      minimum: 1,
                      maximum: 10000,
                      description: "Weighted routing value (for percent-based traffic split)",
                    },
                    geoCidrs: {
                      type: "string",
                      description: "Comma-separated CIDR list for GeoDNS selection by resolver/client subnet",
                    },
                    enabled: { type: "boolean" },
                    healthcheckUrl: {
                      type: "string",
                      format: "uri",
                      description: "Optional HTTP/HTTPS health check endpoint",
                    },
                  },
                  required: ["type", "value"],
                },
              },
            },
          },
          responses: {
            "201": { description: "Record upserted" },
            "400": { description: "Invalid payload" },
            "401": { description: "Unauthorized" },
          },
        },
      },
      "/api/records/{recordId}": {
        put: {
          tags: ["Records"],
          summary: "Update a DNS record",
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: "recordId",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
          ],
          requestBody: {
            required: false,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    host: { type: "string" },
                    type: {
                      type: "string",
                      enum: ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "SRV", "PTR"],
                    },
                    ttl: { type: "integer", minimum: 1, maximum: 86400 },
                    value: { type: "string" },
                    weight: { type: "integer", minimum: 1, maximum: 10000 },
                    geoCidrs: { type: "string" },
                    enabled: { type: "boolean" },
                    healthcheckUrl: { type: "string", format: "uri" },
                  },
                },
              },
            },
          },
          responses: {
            "200": { description: "Record updated" },
            "401": { description: "Unauthorized" },
            "404": { description: "Record not found" },
          },
        },
        delete: {
          tags: ["Records"],
          summary: "Delete a DNS record",
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: "recordId",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
          ],
          responses: {
            "200": { description: "Record deleted" },
            "401": { description: "Unauthorized" },
            "404": { description: "Record not found" },
          },
        },
      },
      "/api/domains/{domainId}/ddns-tokens": {
        get: {
          tags: ["Dynamic DNS"],
          summary: "List DDNS tokens for a domain",
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: "domainId",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
          ],
          responses: {
            "200": { description: "DDNS tokens list" },
            "401": { description: "Unauthorized" },
            "404": { description: "Domain not found" },
          },
        },
        post: {
          tags: ["Dynamic DNS"],
          summary: "Create DDNS token for hostname",
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: "domainId",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
          ],
          requestBody: {
            required: false,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    host: { type: "string", example: "home" },
                    ttl: { type: "integer", minimum: 1, maximum: 86400 },
                  },
                },
              },
            },
          },
          responses: {
            "201": { description: "DDNS token created" },
            "401": { description: "Unauthorized" },
          },
        },
      },
      "/api/ddns-tokens/{tokenId}": {
        delete: {
          tags: ["Dynamic DNS"],
          summary: "Delete a DDNS token",
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: "tokenId",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
          ],
          responses: {
            "200": { description: "Token deleted" },
            "401": { description: "Unauthorized" },
            "404": { description: "Token not found" },
          },
        },
      },
      "/api/dyndns/update": {
        post: {
          tags: ["Dynamic DNS"],
          summary: "Update A record using DDNS token",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    token: { type: "string" },
                    ip: { type: "string", description: "IPv4; optional if inferred from proxy headers" },
                  },
                  required: ["token"],
                },
              },
            },
          },
          responses: {
            "200": { description: "DDNS update result" },
            "400": { description: "Invalid payload/IP" },
            "401": { description: "Invalid token" },
          },
        },
      },
      "/nic/update": {
        get: {
          tags: ["Dynamic DNS"],
          summary: "DynDNS style endpoint",
          description: "Pass DDNS token as Bearer token. Optional `myip` query parameter.",
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: "myip",
              in: "query",
              required: false,
              schema: { type: "string" },
            },
          ],
          responses: {
            "200": { description: "good <ip> or nochg <ip>" },
            "400": { description: "dnserr" },
            "401": { description: "badauth" },
          },
        },
      },
    },
  };
}

export function scalarHtml(openApiUrl: string) {
  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Bun DNS API Docs</title>
  </head>
  <body>
    <script id="api-reference" data-url="${openApiUrl}"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`;
}
