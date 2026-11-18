"""自研 DNS 线协议编解码测试。"""

import struct

import pytest

from app.probe import dns_wire


def _answer(qname: str, qid: int, answers: list[str],
            rcode: int = dns_wire.RCODE_OK) -> bytes:
    return dns_wire.build_response(
        qid, dns_wire.DnsQuestion(qname), rcode=rcode, answers=answers
    )


def test_query_builds_question():
    pkt = dns_wire.build_query("allowed.demo.test", qid=0x1234)
    # 用对应的应答构造器把问题段包回去，验证问题段可被解析
    resp = dns_wire.build_response(
        0x1234,
        dns_wire.DnsQuestion("allowed.demo.test"),
        answers=[],
    )
    # 查询报文问题段与应答报文问题段应完全一致
    assert pkt[12:] == resp[12:]


def test_build_and_parse_a_answer():
    q = dns_wire.build_query("a.test", 7)
    qid = struct.unpack("!H", q[:2])[0]
    msg = dns_wire.parse_message(_answer("a.test", qid, ["172.31.10.10", "172.31.10.11"]))
    assert msg.rcode == dns_wire.RCODE_OK
    assert msg.a_records == ["172.31.10.10", "172.31.10.11"]


def test_nxdomain():
    q = dns_wire.build_query("nope.test", 9)
    qid = struct.unpack("!H", q[:2])[0]
    resp = _answer("nope.test", qid, [], rcode=dns_wire.RCODE_NAME_ERROR)
    msg = dns_wire.parse_message(resp)
    assert msg.rcode == dns_wire.RCODE_NAME_ERROR
    assert msg.a_records == []


def test_compression_pointer_loop_rejected():
    # 构造一个自指压缩指针：answer 名字的两个字节就是指向其自身的指针
    pkt = bytearray()
    pkt += struct.pack("!HHHHHH", 1, 0x8000, 1, 1, 0, 0)
    pkt += b"\x03www\x07example\x03com\x00"
    pkt += struct.pack("!HH", 1, 1)
    answer_name_offset = len(pkt)
    pkt += struct.pack("!H", 0xC000 | answer_name_offset)  # 指向自己 -> 环路
    pkt += struct.pack("!HHIH", 1, 1, 30, 4)
    pkt += b"\x7f\x00\x00\x01"
    with pytest.raises(dns_wire.DnsProtocolError, match="环路"):
        dns_wire.parse_message(bytes(pkt))


def test_truncated_packet_rejected():
    with pytest.raises(dns_wire.DnsProtocolError):
        dns_wire.parse_message(b"\x00" * 5)


def test_label_too_long_rejected():
    with pytest.raises(dns_wire.DnsProtocolError):
        dns_wire._encode_name("a" * 64 + ".test")
