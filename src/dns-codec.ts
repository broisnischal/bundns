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
  if (qtype === QTYPE.A) return record.type === "A" || record.type === "CNAME";
  if (qtype === QTYPE.AAAA) return record.type === "AAAA" || record.type === "CNAME";
  if (qtype === QTYPE.CNAME) return record.type === "CNAME";
  return false;
}

export function buildSuccessResponse(
  context: QueryContext,
  records: DnsRecord[],
  domainExists: boolean,
): Uint8Array {
  const answers = records.filter((record) => shouldAnswerForType(context.qtype, record));
  const rcode = domainExists ? RCODE.NOERROR : RCODE.NXDOMAIN;

  const answerParts: Uint8Array[] = [];
  for (const answer of answers) {
    const nameBytes = encodeName(context.qname);
    const rrHeader = new Uint8Array(10);
    const typeNum =
      answer.type === "A" ? QTYPE.A : answer.type === "AAAA" ? QTYPE.AAAA : QTYPE.CNAME;

    writeU16(rrHeader, 0, typeNum);
    writeU16(rrHeader, 2, QCLASS.IN);
    writeU32(rrHeader, 4, answer.ttl);

    let rdata: Uint8Array;
    if (answer.type === "A") {
      rdata = ipv4ToBytes(answer.value);
    } else if (answer.type === "AAAA") {
      rdata = ipv6ToBytes(answer.value);
    } else {
      rdata = encodeName(answer.value);
    }
    writeU16(rrHeader, 8, rdata.length);
    answerParts.push(nameBytes, rrHeader, rdata);
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
  writeU16(header, 8, 0);
  writeU16(header, 10, 0);

  const totalLength =
    header.length +
    context.questionSection.length +
    answerParts.reduce((sum, part) => sum + part.length, 0);

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
