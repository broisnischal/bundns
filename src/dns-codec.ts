import { QCLASS, QTYPE, RCODE } from "./constants";
import type { DnsRecord, QueryContext } from "./types";

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

function u16(view: DataView, offset: number) {
  return view.getUint16(offset, false);
}

function writeU16(buf: Uint8Array, offset: number, value: number) {
  buf[offset] = (value >> 8) & 0xff;
  buf[offset + 1] = value & 0xff;
}

function writeU32(buf: Uint8Array, offset: number, value: number) {
  buf[offset] = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

function decodeName(bytes: Uint8Array, start: number): { name: string; next: number } {
  let offset = start;
  let jumped = false;
  let jumpNext = 0;
  const labels: string[] = [];
  let guard = 0;

  while (guard++ < 200) {
    if (offset >= bytes.length) {
      throw new Error("Name decode out of range");
    }

    const len = bytes[offset];
    if (len === 0) {
      offset += 1;
      break;
    }

    if ((len & 0xc0) === 0xc0) {
      if (offset + 1 >= bytes.length) {
        throw new Error("Compression pointer out of range");
      }
      const ptr = ((len & 0x3f) << 8) | bytes[offset + 1];
      if (!jumped) {
        jumpNext = offset + 2;
        jumped = true;
      }
      offset = ptr;
      continue;
    }

    const labelEnd = offset + 1 + len;
    if (labelEnd > bytes.length) {
      throw new Error("Label out of range");
    }
    labels.push(textDecoder.decode(bytes.slice(offset + 1, labelEnd)));
    offset = labelEnd;
  }

  if (guard >= 200) {
    throw new Error("Name decode guard reached");
  }

  const name = labels.length ? `${labels.join(".")}.` : ".";
  return { name, next: jumped ? jumpNext : offset };
}

function encodeName(name: string): Uint8Array {
  const normalized = name.endsWith(".") ? name.slice(0, -1) : name;
  if (!normalized) {
    return Uint8Array.of(0);
  }

  const chunks: number[] = [];
  for (const part of normalized.split(".")) {
    const bytes = textEncoder.encode(part);
    chunks.push(bytes.length, ...bytes);
  }
  chunks.push(0);
  return Uint8Array.from(chunks);
}

function ipv4ToBytes(ip: string): Uint8Array {
  const parts = ip.split(".").map((x) => Number(x));
  if (parts.length !== 4 || parts.some((x) => Number.isNaN(x) || x < 0 || x > 255)) {
    throw new Error(`Invalid IPv4: ${ip}`);
  }
  return Uint8Array.from(parts);
}

function ipv6ToBytes(ip: string): Uint8Array {
  const [left, right] = ip.split("::");
  const leftParts = left ? left.split(":").filter(Boolean) : [];
  const rightParts = right ? right.split(":").filter(Boolean) : [];
  const fill = 8 - (leftParts.length + rightParts.length);

  if (fill < 0) {
    throw new Error(`Invalid IPv6: ${ip}`);
  }

  const parts = [
    ...leftParts,
    ...Array.from({ length: fill }, () => "0"),
    ...rightParts,
  ].map((part) => parseInt(part || "0", 16));

  if (parts.length !== 8 || parts.some((x) => Number.isNaN(x) || x < 0 || x > 0xffff)) {
    throw new Error(`Invalid IPv6: ${ip}`);
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (parts[i] >> 8) & 0xff;
    out[i * 2 + 1] = parts[i] & 0xff;
  }
  return out;
}

function encodeTxtData(value: string): Uint8Array {
  const raw = value.replace(/^"(.*)"$/, "$1");
  const bytes = textEncoder.encode(raw);
  if (bytes.length === 0) {
    return Uint8Array.of(0);
  }
  const parts: number[] = [];
  for (let offset = 0; offset < bytes.length; offset += 255) {
    const len = Math.min(255, bytes.length - offset);
    parts.push(len);
    for (let i = 0; i < len; i++) {
      parts.push(bytes[offset + i]);
    }
  }
  return Uint8Array.from(parts);
}

function parseTwoPartRdata(value: string, recordType: string): { n1: number; n2: string } {
  const parts = value.trim().split(/\s+/);
  if (parts.length !== 2) {
    throw new Error(`Invalid ${recordType} value`);
  }
  const n1 = Number(parts[0]);
  if (!Number.isInteger(n1) || n1 < 0 || n1 > 65535) {
    throw new Error(`Invalid ${recordType} preference`);
  }
  return { n1, n2: parts[1] };
}

function parseSoa(value: string) {
  const parts = value.trim().split(/\s+/);
  if (parts.length !== 7) {
    throw new Error("Invalid SOA value");
  }
  const nums = parts.slice(2).map((part) => Number(part));
  if (nums.some((v) => !Number.isInteger(v) || v < 0 || v > 0xffffffff)) {
    throw new Error("Invalid SOA numeric values");
  }
  return {
    mname: parts[0],
    rname: parts[1],
    serial: nums[0],
    refresh: nums[1],
    retry: nums[2],
    expire: nums[3],
    minimum: nums[4],
  };
}

function parseSrv(value: string) {
  const parts = value.trim().split(/\s+/);
  if (parts.length !== 4) {
    throw new Error("Invalid SRV value");
  }
  const [priority, weight, port] = parts.slice(0, 3).map((part) => Number(part));
  if (
    [priority, weight, port].some(
      (v) => !Number.isInteger(v) || v < 0 || v > 65535,
    )
  ) {
    throw new Error("Invalid SRV numeric values");
  }
  return { priority, weight, port, target: parts[3] };
}

function parseCaa(value: string) {
  const match = value.trim().match(/^(\d+)\s+([a-zA-Z0-9-]+)\s+(.+)$/);
  if (!match) {
    throw new Error("Invalid CAA value");
  }
  const flags = Number(match[1]);
  const tag = match[2];
  const caaValue = match[3].replace(/^"(.*)"$/, "$1");
  if (!Number.isInteger(flags) || flags < 0 || flags > 255) {
    throw new Error("Invalid CAA flags");
  }
  const tagBytes = textEncoder.encode(tag);
  if (tagBytes.length < 1 || tagBytes.length > 255) {
    throw new Error("Invalid CAA tag");
  }
  return { flags, tagBytes, valueBytes: textEncoder.encode(caaValue) };
}

function typeToQtype(type: DnsRecord["type"]) {
  switch (type) {
    case "A":
      return QTYPE.A;
    case "AAAA":
      return QTYPE.AAAA;
    case "CNAME":
      return QTYPE.CNAME;
    case "NS":
      return QTYPE.NS;
    case "SOA":
      return QTYPE.SOA;
    case "MX":
      return QTYPE.MX;
    case "TXT":
      return QTYPE.TXT;
    case "CAA":
      return QTYPE.CAA;
    case "SRV":
      return QTYPE.SRV;
    case "PTR":
      return QTYPE.PTR;
  }
}

function encodeRdata(record: DnsRecord): Uint8Array {
  switch (record.type) {
    case "A":
      return ipv4ToBytes(record.value);
    case "AAAA":
      return ipv6ToBytes(record.value);
    case "CNAME":
    case "NS":
    case "PTR":
      return encodeName(record.value);
    case "SOA": {
      const soa = parseSoa(record.value);
      const mname = encodeName(soa.mname);
      const rname = encodeName(soa.rname);
      const tail = new Uint8Array(20);
      writeU32(tail, 0, soa.serial);
      writeU32(tail, 4, soa.refresh);
      writeU32(tail, 8, soa.retry);
      writeU32(tail, 12, soa.expire);
      writeU32(tail, 16, soa.minimum);
      const out = new Uint8Array(mname.length + rname.length + tail.length);
      out.set(mname, 0);
      out.set(rname, mname.length);
      out.set(tail, mname.length + rname.length);
      return out;
    }
    case "MX": {
      const { n1: preference, n2: exchange } = parseTwoPartRdata(record.value, "MX");
      const exchangeBytes = encodeName(exchange);
      const out = new Uint8Array(2 + exchangeBytes.length);
      writeU16(out, 0, preference);
      out.set(exchangeBytes, 2);
      return out;
    }
    case "TXT":
      return encodeTxtData(record.value);
    case "CAA": {
      const caa = parseCaa(record.value);
      const out = new Uint8Array(2 + caa.tagBytes.length + caa.valueBytes.length);
      out[0] = caa.flags;
      out[1] = caa.tagBytes.length;
      out.set(caa.tagBytes, 2);
      out.set(caa.valueBytes, 2 + caa.tagBytes.length);
      return out;
    }
    case "SRV": {
      const srv = parseSrv(record.value);
      const targetBytes = encodeName(srv.target);
      const out = new Uint8Array(6 + targetBytes.length);
      writeU16(out, 0, srv.priority);
      writeU16(out, 2, srv.weight);
      writeU16(out, 4, srv.port);
      out.set(targetBytes, 6);
      return out;
    }
  }
}

export function parseQuery(query: Uint8Array): QueryContext | null {
  if (query.length < 12) return null;

  const view = new DataView(query.buffer, query.byteOffset, query.byteLength);
  const id = u16(view, 0);
  const flags = u16(view, 2);
  const qdcount = u16(view, 4);

  if (qdcount !== 1) {
    return null;
  }

  const qr = (flags >> 15) & 1;
  if (qr !== 0) {
    return null;
  }

  let qname: string;
  let next: number;
  try {
    ({ name: qname, next } = decodeName(query, 12));
  } catch {
    return null;
  }
  if (next + 4 > query.length) {
    return null;
  }

  const qtype = u16(view, next);
  const qclass = u16(view, next + 2);
  const questionSection = query.slice(12, next + 4);

  return {
    id,
    flags,
    qtype,
    qclass,
    qname,
    questionSection,
  };
}

function shouldAnswerForType(qtype: number, record: DnsRecord) {
  if (qtype === QTYPE.ANY) return true;
  if (qtype === QTYPE.A) return record.type === "A" || record.type === "CNAME";
  if (qtype === QTYPE.AAAA) return record.type === "AAAA" || record.type === "CNAME";
  if (qtype === QTYPE.CNAME) return record.type === "CNAME";
  if (qtype === QTYPE.NS) return record.type === "NS";
  if (qtype === QTYPE.SOA) return record.type === "SOA";
  if (qtype === QTYPE.MX) return record.type === "MX";
  if (qtype === QTYPE.TXT) return record.type === "TXT";
  if (qtype === QTYPE.CAA) return record.type === "CAA";
  if (qtype === QTYPE.SRV) return record.type === "SRV";
  if (qtype === QTYPE.PTR) return record.type === "PTR";
  return false;
}

function encodeRecord(ownerName: string, record: DnsRecord): Uint8Array[] {
  const nameBytes = encodeName(ownerName);
  const rrHeader = new Uint8Array(10);
  writeU16(rrHeader, 0, typeToQtype(record.type));
  writeU16(rrHeader, 2, QCLASS.IN);
  writeU32(rrHeader, 4, record.ttl);
  const rdata = encodeRdata(record);
  writeU16(rrHeader, 8, rdata.length);
  return [nameBytes, rrHeader, rdata];
}

export function buildSuccessResponse(
  context: QueryContext,
  records: DnsRecord[],
  authorityRecords: DnsRecord[],
  zoneExists: boolean,
  zoneName: string | null,
): Uint8Array {
  const answers = records.filter((record) => shouldAnswerForType(context.qtype, record));
  const rcode = zoneExists ? RCODE.NOERROR : RCODE.NXDOMAIN;
  const authority =
    answers.length === 0
      ? authorityRecords.filter((record) => record.type === "SOA" || record.type === "NS")
      : [];

  const answerParts: Uint8Array[] = [];
  for (const answer of answers) {
    answerParts.push(...encodeRecord(context.qname, answer));
  }

  const authorityParts: Uint8Array[] = [];
  const authorityName = zoneName ?? context.qname;
  for (const auth of authority) {
    authorityParts.push(...encodeRecord(authorityName, auth));
  }

  const rd = (context.flags >> 8) & 1;
  const respFlags =
    (1 << 15) | // QR
    (0 << 11) | // OPCODE
    (1 << 10) | // AA
    (0 << 9) | // TC
    (rd << 8) | // RD copied
    (0 << 7) | // RA
    (rcode & 0x0f);

  const header = new Uint8Array(12);
  writeU16(header, 0, context.id);
  writeU16(header, 2, respFlags);
  writeU16(header, 4, 1);
  writeU16(header, 6, answers.length);
  writeU16(header, 8, authority.length);
  writeU16(header, 10, 0);

  const totalLength =
    header.length +
    context.questionSection.length +
    answerParts.reduce((sum, part) => sum + part.length, 0) +
    authorityParts.reduce((sum, part) => sum + part.length, 0);

  const out = new Uint8Array(totalLength);
  let offset = 0;
  out.set(header, offset);
  offset += header.length;
  out.set(context.questionSection, offset);
  offset += context.questionSection.length;
  for (const part of answerParts) {
    out.set(part, offset);
    offset += part.length;
  }
  for (const part of authorityParts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function buildErrorResponse(id: number, rcode: number): Uint8Array {
  const header = new Uint8Array(12);
  const respFlags =
    (1 << 15) | // QR
    (1 << 10) | // AA
    (rcode & 0x0f);

  writeU16(header, 0, id);
  writeU16(header, 2, respFlags);
  writeU16(header, 4, 0);
  writeU16(header, 6, 0);
  writeU16(header, 8, 0);
  writeU16(header, 10, 0);
  return header;
}

export function isSupportedClass(qclass: number) {
  return qclass === QCLASS.IN;
}
