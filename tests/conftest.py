"""集成测试夹具：本地假 DNS + HTTP/HTTPS 服务器 + 证书。"""

from __future__ import annotations

import asyncio
import os
import ssl
from pathlib import Path

import pytest
import pytest_asyncio

from app.probe import dns_wire
from app.probe.config import Settings
from app.probe.dns_client import DnsResolver
from app.probe.http_probe import Prober
from app.probe.policy import AddressPolicy


# ---------------------------------------------------------------- DNS 假服务
class FakeDns:
    """可热切换 zones 的 UDP/53 假解析器。"""

    def __init__(self) -> None:
        self.zones: dict[str, list[str]] = {}
        self._transport: asyncio.DatagramTransport | None = None
        self.queried_names: list[str] = []

    def set_zones(self, zones: dict[str, list[str]]) -> None:
        self.zones = {k.lower(): list(v) for k, v in zones.items()}

    def connection_made(self, transport):  # noqa: ANN001
        self._transport = transport

    def connection_lost(self, exc) -> None:  # noqa: ANN001
        self._transport = None

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        try:
            msg = dns_wire.parse_message(data, require_qr=False)
            q = msg.questions[0]
            self.queried_names.append(q.qname)
            if q.qname.lower() in self.zones:
                reply = dns_wire.build_response(
                    msg.qid, q, answers=self.zones[q.qname.lower()]
                )
            else:
                reply = dns_wire.build_response(
                    msg.qid, q, rcode=dns_wire.RCODE_NAME_ERROR
                )
        except (dns_wire.DnsProtocolError, IndexError):
            return
        assert self._transport is not None
        self._transport.sendto(reply, addr)


# ------------------------------------------------------------- HTTP 测试服务
class FakeHttpServer:
    """按 (host, path) 返回预置响应的 HTTP/HTTPS 服务器，并记录请求。"""

    def __init__(self, ssl_ctx: ssl.SSLContext | None = None) -> None:
        self.routes: dict[tuple[str, str], tuple[int, list[tuple[str, str]], str]] = {}
        self.requests: list[dict] = []
        self.ssl_ctx = ssl_ctx
        self._server: asyncio.base_events.Server | None = None

    def route(self, host: str, path: str, status: int = 200,
              headers: list[tuple[str, str]] | None = None, body: str = "ok") -> None:
        self.routes[(host.lower(), path)] = (status, headers or [], body)

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await reader.readline()
            if not request_line:
                return
            method, path, _ = request_line.decode().split(" ", 2)
            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                k, v = line.decode().split(":", 1)
                headers[k.strip().lower()] = v.strip()
            host = headers.get("host", "").split(":")[0].lower()
            self.requests.append({"method": method, "host": host, "path": path})
            status, extra_headers, body = self.routes.get(
                (host, path), (404, [], "not found")
            )
            resp = [f"HTTP/1.1 {status} X\r\n", f"Content-Length: {len(body)}\r\n",
                    "Connection: close\r\n"]
            for k, v in extra_headers:
                resp.append(f"{k}: {v}\r\n")
            resp.append("\r\n")
            resp.append(body)
            writer.write("".join(resp).encode())
            await writer.drain()
        except (ConnectionError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, ssl=self.ssl_ctx
        )
        sock = self._server.sockets[0]
        return sock.getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


# ------------------------------------------------------------------- 证书
@pytest.fixture()
def demo_certs(tmp_path: Path) -> tuple[Path, Path, Path]:
    """生成演示 CA 与服务器证书，返回 (certfile, keyfile, cafile)。"""
    from app.certinit.generate_certs import main as gen_main

    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    os.environ["CERT_DIR"] = str(cert_dir)
    os.environ["CERT_DAYS"] = "30"
    gen_main()
    return (
        cert_dir / "targets.fullchain.pem",
        cert_dir / "targets.key.pem",
        cert_dir / "demo-ca.crt.pem",
    )


@pytest_asyncio.fixture()
async def fake_dns() -> FakeDns:
    loop = asyncio.get_running_loop()
    dns = FakeDns()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: dns, local_addr=("127.0.0.1", 0)
    )
    dns._transport = transport
    port = transport.get_extra_info("socket").getsockname()[1]
    try:
        dns.port = port
        yield dns
    finally:
        transport.close()


@pytest_asyncio.fixture()
async def http_server() -> FakeHttpServer:
    srv = FakeHttpServer()
    await srv.start()
    srv.port = srv._server.sockets[0].getsockname()[1]
    try:
        yield srv
    finally:
        await srv.stop()


@pytest_asyncio.fixture()
async def https_server(demo_certs) -> FakeHttpServer:
    certfile, keyfile, _cafile = demo_certs
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certfile), str(keyfile))
    srv = FakeHttpServer(ssl_ctx=ctx)
    await srv.start()
    srv.port = srv._server.sockets[0].getsockname()[1]
    try:
        yield srv
    finally:
        await srv.stop()


@pytest.fixture()
def make_prober(fake_dns, demo_certs):
    """构造只允许 127.0.0.1/32 的 Prober 工厂。"""
    _cert, _key, cafile = demo_certs

    def _factory(allowed=("127.0.0.1/32",), max_redirects: int = 3,
                 read_timeout: float = 5.0) -> Prober:
        settings = Settings(
            policy=AddressPolicy.from_cidrs(list(allowed)),
            dns_server="127.0.0.1",
            dns_port=fake_dns.port,
            dns_timeout=2.0,
            dns_retries=0,
            ca_bundle=str(cafile),
            connect_timeout=3.0,
            read_timeout=read_timeout,
            tls_timeout=5.0,
            max_redirects=max_redirects,
            max_concurrency=8,
            overall_timeout=20.0,
        )
        resolver = DnsResolver("127.0.0.1", port=fake_dns.port, retries=0)
        return Prober(
            policy=settings.policy,
            resolver=resolver,
            ca_bundle=str(cafile),
            connect_timeout=3.0,
            read_timeout=read_timeout,
            tls_timeout=5.0,
            max_redirects=max_redirects,
        )

    return _factory
