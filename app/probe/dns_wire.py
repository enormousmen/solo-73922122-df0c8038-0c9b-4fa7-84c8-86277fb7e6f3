"""极简 DNS 线协议（RFC 1035 子集），仅支持 A 记录查询与应答。

探测端只向 *配置指定的解析器* 发 UDP 查询，绝不使用系统 getaddrinfo，
从而保证“先校验、后连接”的地址完全来自可见的 DNS 应答。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

TYPE_A = 1
CLASS_IN = 1
RCODE_OK = 0
RCODE_NAME_ERROR = 3  # NXDOMAIN
RCODE_SERVFAIL = 2

FLAGS_QR = 0x8000
FLAGS_AA = 0x0400
FLAGS_RD = 0x0100
FLAGS_RA = 0x0080


class DnsProtocolError(Exception):
    pass


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.strip(".").split("."):
        if not label:
            continue
        if len(label) > 63:
            raise DnsProtocolError(f"域名标签过长: {label!r}")
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """读取 QNAME，支持压缩指针，返回 (name, 下一偏移)。"""
    labels: list[str] = []
    seen_pointers = 0
    cur = offset
    jumped = False
    next_off = 0
    while True:
        if cur >= len(data):
            raise DnsProtocolError("域名解析越界")
        length = data[cur]
        if length == 0:
            cur += 1
            if not jumped:
                next_off = cur
            break
        if length & 0xC0 == 0xC0:
            if cur + 1 >= len(data):
                raise DnsProtocolError("压缩指针截断")
            ptr = ((length & 0x3F) << 8) | data[cur + 1]
            if not jumped:
                next_off = cur + 2
            cur = ptr
            jumped = True
            seen_pointers += 1
            if seen_pointers > 16:
                raise DnsProtocolError("压缩指针环路")
            continue
        if length & 0xC0:
            raise DnsProtocolError("不支持的标签类型")
        cur += 1
        labels.append(data[cur : cur + length].decode("ascii"))
        cur += length
    return ".".join(labels), (next_off if jumped else cur)


@dataclass
class DnsQuestion:
    qname: str
    qtype: int = TYPE_A
    qclass: int = CLASS_IN


@dataclass
class DnsRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes


@dataclass
class DnsMessage:
    qid: int
    flags: int
    rcode: int
    questions: list[DnsQuestion]
    answers: list[DnsRecord]

    @property
    def a_records(self) -> list[str]:
        import ipaddress

        out: list[str] = []
        for rec in self.answers:
            if rec.rtype == TYPE_A and rec.rclass == CLASS_IN and len(rec.rdata) == 4:
                out.append(str(ipaddress.ip_address(rec.rdata)))
        return out


def build_query(qname: str, qid: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, FLAGS_RD, 1, 0, 0, 0)
    return header + _encode_name(qname) + struct.pack("!HH", TYPE_A, CLASS_IN)


def parse_message(data: bytes, require_qr: bool = True) -> DnsMessage:
    if len(data) < 12:
        raise DnsProtocolError("DNS 报文短于头部")
    qid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )
    if require_qr and not flags & FLAGS_QR:
        raise DnsProtocolError("不是 DNS 应答报文")
    rcode = flags & 0x000F
    offset = 12
    questions: list[DnsQuestion] = []
    for _ in range(qdcount):
        name, offset = _read_name(data, offset)
        if offset + 4 > len(data):
            raise DnsProtocolError("问题段截断")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append(DnsQuestion(name, qtype, qclass))
    answers: list[DnsRecord] = []
    for _ in range(ancount):
        name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise DnsProtocolError("应答段截断")
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        if len(rdata) != rdlen:
            raise DnsProtocolError("RDATA 截断")
        offset += rdlen
        answers.append(DnsRecord(name, rtype, rclass, ttl, rdata))
    return DnsMessage(qid, flags, rcode, questions, answers)


def build_response(
    qid: int,
    question: DnsQuestion | None,
    rcode: int = RCODE_OK,
    answers: list[str] | None = None,
    ttl: int = 30,
) -> bytes:
    """构造一个仅含 A 记录应答的报文（演示用本地解析器）。"""
    answers = answers or []
    ancount = len(answers) if rcode == RCODE_OK else 0
    flags = FLAGS_QR | FLAGS_AA | FLAGS_RD | FLAGS_RA | rcode
    out = bytearray(struct.pack("!HHHHHH", qid, flags, 1 if question else 0, ancount, 0, 0))
    if question is not None:
        out += _encode_name(question.qname)
        out += struct.pack("!HH", question.qtype, question.qclass)
        for ip in answers:
            import ipaddress

            addr = ipaddress.ip_address(ip)
            if addr.version != 4:
                raise DnsProtocolError("演示解析器仅支持 A 记录")
            out += _encode_name(question.qname)
            out += struct.pack("!HHIH", TYPE_A, CLASS_IN, ttl, 4)
            out += addr.packed
    return bytes(out)
