export type RecordA = { type: "A"; ttl: number; value: string };
export type RecordAAAA = { type: "AAAA"; ttl: number; value: string };
export type RecordCNAME = { type: "CNAME"; ttl: number; value: string };
export type RecordNS = { type: "NS"; ttl: number; value: string };
export type RecordSOA = { type: "SOA"; ttl: number; value: string };
export type RecordMX = { type: "MX"; ttl: number; value: string };
export type RecordTXT = { type: "TXT"; ttl: number; value: string };
export type RecordCAA = { type: "CAA"; ttl: number; value: string };
export type RecordSRV = { type: "SRV"; ttl: number; value: string };
export type RecordPTR = { type: "PTR"; ttl: number; value: string };

export type DnsRecord =
  | RecordA
  | RecordAAAA
  | RecordCNAME
  | RecordNS
  | RecordSOA
  | RecordMX
  | RecordTXT
  | RecordCAA
  | RecordSRV
  | RecordPTR;

export type DnsRecordType = DnsRecord["type"];

export type ParsedQuestion = {
  name: string;
  qtype: number;
  qclass: number;
  questionEndOffset: number;
  id: number;
  flags: number;
};

export type QueryContext = {
  id: number;
  flags: number;
  qtype: number;
  qclass: number;
  qname: string;
  questionSection: Uint8Array;
};
