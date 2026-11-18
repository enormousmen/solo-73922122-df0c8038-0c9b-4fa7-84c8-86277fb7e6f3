"""异步 DNS 客户端：向显式配置的解析器发 A 记录查询。

刻意不使用 socket.getaddrinfo / asyncio 内置 DNS，原因：
1. 系统解析器不受白名单策略控制，且可能返回 IPv6；
2. 我们要求拿到 *完整* 的应答地址列表逐个校验，而不是让运行时
   自行挑选一个连接（运行时重试可能在检查后换到未获准地址）。
"""

from __future__ import annotations

import asyncio
import os
import random

from . import dns_wire
from .policy import PolicyError, is_ip_literal


class DnsError(PolicyError):
    """解析失败（超时、SERVFAIL、NXDOMAIN、应答异常等）。"""


class DnsResolver:
    def __init__(
        self,
        server_ip: str,
        port: int = 53,
        timeout: float = 3.0,
        retries: int = 1,
    ) -> None:
        if not is_ip_literal(server_ip):
            raise ValueError("DNS 解析器必须配置为 IP 字面量，避免自举解析")
        self._server = (server_ip, port)
        self._timeout = timeout
        self._retries = retries

    async def resolve_a(self, hostname: str) -> list[str]:
        """返回 A 记录地址列表；无记录或失败时抛 DnsError。"""
        hostname = hostname.lower().rstrip(".")
        last_error: Exception | None = None
        for attempt in range(self._retries + 1):
            qid = random.randint(0, 65535)
            packet = dns_wire.build_query(hostname, qid)
            try:
                data = await self._exchange(packet, qid, hostname)
            except DnsError as exc:
                last_error = exc
                continue
            msg = dns_wire.parse_message(data)
            if msg.rcode == dns_wire.RCODE_NAME_ERROR:
                raise DnsError(f"DNS NXDOMAIN: 域名 {hostname!r} 不存在")
            if msg.rcode != dns_wire.RCODE_OK:
                raise DnsError(f"DNS 应答错误 rcode={msg.rcode}（域名 {hostname!r}）")
            ips = msg.a_records
            if not ips:
                raise DnsError(f"DNS 应答中没有可用的 A 记录: {hostname!r}")
            # 去重但保持顺序，便于报告展示
            seen: set[str] = set()
            unique: list[str] = []
            for ip in ips:
                if ip not in seen:
                    seen.add(ip)
                    unique.append(ip)
            return unique
        raise DnsError(
            f"DNS 查询 {hostname!r} 在 {self._retries + 1} 次尝试后仍失败: {last_error}"
        )

    async def _exchange(self, packet: bytes, qid: int, hostname: str) -> bytes:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bytes] = loop.create_future()
        transport, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: _UdpClient(future, qid, hostname),
                remote_addr=self._server,
            ),
            timeout=self._timeout,
        )
        try:
            transport.sendto(packet)
            return await asyncio.wait_for(future, timeout=self._timeout)
        except asyncio.TimeoutError as exc:
            raise DnsError(
                f"DNS 查询超时（解析器 {self._server[0]}:{self._server[1]}）"
            ) from exc
        finally:
            transport.close()


class _UdpClient(asyncio.DatagramProtocol):
    def __init__(self, future: "asyncio.Future[bytes]", qid: int, hostname: str) -> None:
        self._future = future
        self._qid = qid
        self._hostname = hostname

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        if self._future.done():
            return
        if len(data) < 2 or int.from_bytes(data[:2], "big") != self._qid:
            return
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(DnsError(f"DNS socket 错误: {exc}"))


def resolver_from_env() -> DnsResolver:
    server = os.getenv("DNS_SERVER", "127.0.0.1").strip()
    port = int(os.getenv("DNS_PORT", "53"))
    timeout = float(os.getenv("DNS_TIMEOUT", "3.0"))
    retries = int(os.getenv("DNS_RETRIES", "1"))
    return DnsResolver(server, port=port, timeout=timeout, retries=retries)
