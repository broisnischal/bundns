export type RecordA = { type: "A"; ttl: number; value: string };
export type RecordAAAA = { type: "AAAA"; ttl: number; value: string };
export type RecordCNAME = { type: "CNAME"; ttl: number; value: string };

export type DnsRecord = RecordA | RecordAAAA | RecordCNAME;

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
