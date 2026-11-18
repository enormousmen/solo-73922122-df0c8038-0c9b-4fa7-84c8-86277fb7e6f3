"""FastAPI 接口层测试。

TestClient 会在独立线程的独立事件循环中运行应用，因此所有本地假服务
（DNS/UDP、HTTP/TCP）都通过应用的 lifespan 钩子在 *同一* 循环内创建。
"""

from __future__ import annotations

import asyncio
import importlib
import os
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

from app.probe import dns_wire


class InLoopDns:
    def __init__(self) -> None:
        self.zones: dict[str, list[str]] = {}
        self._transport = None

    def connection_made(self, transport):  # noqa: ANN001
        self._transport = transport

    def connection_lost(self, exc) -> None:  # noqa: ANN001
        self._transport = None

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        msg = dns_wire.parse_message(data, require_qr=False)
        q = msg.questions[0]
        if q.qname.lower() in self.zones:
            reply = dns_wire.build_response(msg.qid, q, answers=self.zones[q.qname.lower()])
        else:
            reply = dns_wire.build_response(
                msg.qid, q, rcode=dns_wire.RCODE_NAME_ERROR
            )
        self._transport.sendto(reply, addr)


class InLoopHttp:
    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], tuple[int, dict, str, float]] = {}
        self.requests: list[dict] = []
        self._server = None
        self.port = 0

    def route(self, host, path, status=200, headers=None, body="ok", delay=0.0):  # noqa: ANN001
        self.routes[(host.lower(), path)] = (status, headers or {}, body, delay)

    async def _handle(self, reader, writer):  # noqa: ANN001
        try:
            line = await reader.readline()
            if not line:
                return
            method, path, _ = line.decode().split(" ", 2)
            headers = {}
            while True:
                h = await reader.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
                k, v = h.decode().split(":", 1)
                headers[k.strip().lower()] = v.strip()
            host = headers.get("host", "").split(":")[0].lower()
            self.requests.append({"method": method, "host": host, "path": path})
            status, extra, body, delay = self.routes.get(
                (host, path), (404, {}, "nf", 0.0)
            )
            if delay:
                # 收下请求后挂起：模拟“请求已发出却没有响应”的目标
                await asyncio.sleep(delay)
            head = [
                f"HTTP/1.1 {status} X\r\n",
                f"Content-Length: {len(body)}\r\n",
                "Connection: close\r\n",
            ]
            for k, v in extra.items():
                head.append(f"{k}: {v}\r\n")
            head.append("\r\n")
            head.append(body)
            writer.write("".join(head).encode())
            await writer.drain()
        except (ConnectionError, ValueError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()


def _build_client(monkeypatch, demo_certs, *, overall_timeout: float,
                  read_timeout: float) -> TestClient:
    _cert, _key, cafile = demo_certs
    dns = InLoopDns()
    httpd = InLoopHttp()

    import app.probe.main as main_mod

    @asynccontextmanager
    async def test_lifespan(app):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: dns, local_addr=("127.0.0.1", 0)
        )
        dns._transport = transport
        dns_port = transport.get_extra_info("socket").getsockname()[1]
        await httpd.start()

        monkeypatch.setenv("ALLOWED_CIDRS", "127.0.0.1/32")
        monkeypatch.setenv("DNS_SERVER", "127.0.0.1")
        monkeypatch.setenv("DNS_PORT", str(dns_port))
        monkeypatch.setenv("DNS_RETRIES", "0")
        monkeypatch.setenv("DNS_TIMEOUT", "2.0")
        monkeypatch.setenv("CA_BUNDLE", str(cafile))
        monkeypatch.setenv("CONNECT_TIMEOUT", "3.0")
        monkeypatch.setenv("READ_TIMEOUT", str(read_timeout))
        monkeypatch.setenv("TLS_TIMEOUT", "5.0")
        monkeypatch.setenv("PROBE_OVERALL_TIMEOUT", str(overall_timeout))

        import app.probe.config as config_mod
        import app.probe.dns_client as dns_client_mod

        importlib.reload(config_mod)
        importlib.reload(dns_client_mod)
        importlib.reload(main_mod)
        main_mod.app.router.lifespan_context = test_lifespan
        try:
            yield
        finally:
            transport.close()
            await httpd.stop()

    main_mod.app.router.lifespan_context = test_lifespan
    dns.zones = {"api-good.test": ["127.0.0.1"]}
    httpd.route("api-good.test", "/")
    c = TestClient(main_mod.app)
    c.__enter__()
    c._dns = dns
    c._http = httpd
    return c


@pytest.fixture()
def client(monkeypatch, demo_certs):
    c = _build_client(
        monkeypatch, demo_certs, overall_timeout=15.0, read_timeout=5.0
    )
    try:
        yield c
    finally:
        c.__exit__(None, None, None)


@pytest.fixture()
def timeout_client(monkeypatch, demo_certs):
    """总超时很短、读超时很长的客户端：用于验证 408 的逐跳报告。"""
    c = _build_client(
        monkeypatch, demo_certs, overall_timeout=0.6, read_timeout=10.0
    )
    try:
        yield c
    finally:
        c.__exit__(None, None, None)


def test_healthz(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_policy_endpoint(client):
    body = client.get("/api/v1/policy").json()
    assert body["allowed_cidrs"] == ["127.0.0.1/32"]
    assert body["ip_versions"] == ["IPv4"]
    assert body["max_redirects"] == 3
    assert body["tls_verify"] is True


def test_probe_ok(client):
    port = client._http.port
    r = client.post("/api/v1/probe", json={"url": f"http://api-good.test:{port}/"})
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "ok"
    assert body["hops"][0]["connected_peer"] == f"127.0.0.1:{port}"
    assert body["hops"][0]["resolved_addresses"] == ["127.0.0.1"]
    assert client._http.requests[-1]["host"] == "api-good.test"


def test_probe_blocked_reports_reason(client):
    client._dns.zones = {"api-bad.test": ["8.8.8.8"]}
    r = client.post("/api/v1/probe", json={"url": "http://api-bad.test/"})
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "blocked"
    assert "白名单" in body["summary"]
    assert body["hops"][-1]["request_sent"] is False
    assert all(req["host"] != "api-bad.test" for req in client._http.requests)


def test_probe_blocked_returns_structured_hop(client):
    client._dns.zones = {"api-mix.test": ["127.0.0.1", "9.9.9.9"]}
    body = client.post(
        "/api/v1/probe", json={"url": "http://api-mix.test/"}
    ).json()
    assert body["outcome"] == "blocked"
    hop = body["hops"][-1]
    assert hop["resolved_addresses"] == ["127.0.0.1", "9.9.9.9"]
    assert hop["approved_addresses"] == []
    assert hop["connected_peer"] is None


def test_probe_invalid_scheme_reported(client):
    # 非法 scheme 在跳内被静态拦截，返回结构化 blocked（不产生流量）
    r = client.post("/api/v1/probe", json={"url": "ftp://api-good.test/"})
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "blocked"
    assert body["hops"][-1]["request_sent"] is False


def test_probe_bad_method_422(client):
    r = client.post(
        "/api/v1/probe",
        json={"url": "http://api-good.test/", "method": "POST"},
    )
    assert r.status_code == 422


def test_openapi_docs_available(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


# ------------------------------------------------- 总超时（408）逐跳报告
def _slow_redirect_setup(c: TestClient, *, slow_delay: float = 5.0) -> str:
    """首跳 302 -> 第二跳收到请求后挂起，返回首跳 URL。"""
    slow_host = "api-slow.test"
    start_host = "api-start.test"
    c._dns.zones = {slow_host: ["127.0.0.1"], start_host: ["127.0.0.1"]}
    port = c._http.port
    c._http.route(
        start_host,
        "/go",
        status=302,
        headers={"Location": f"http://{slow_host}:{port}/hang"},
    )
    c._http.route(slow_host, "/hang", delay=slow_delay)
    return f"http://{start_host}:{port}/go"


def test_overall_timeout_408_includes_per_hop_progress(timeout_client):
    client = timeout_client
    url = _slow_redirect_setup(client)
    before = len(client._http.requests)

    r = client.post("/api/v1/probe", json={"url": url})

    assert r.status_code == 408
    body = r.json()["detail"]
    assert body["outcome"] == "timeout"
    assert body["timeout_hop"] == 2
    assert body["requested_url"] == url
    hops = body["hops"]
    assert len(hops) == 2

    # 第 1 跳已完成：保留真实状态码/解析地址/连接地址/请求已发送
    first = hops[0]
    assert first["outcome"] == "redirected"
    assert first["status_code"] == 302
    assert first["resolved_addresses"] == ["127.0.0.1"]
    assert first["approved_addresses"] == ["127.0.0.1"]
    assert first["connected_peer"] == f"127.0.0.1:{client._http.port}"
    assert first["request_sent"] is True
    assert first["location"].endswith("/hang")

    # 第 2 跳超时：解析与连接已完成、请求确实发出，但绝不判可达
    second = hops[1]
    assert second["outcome"] == "timeout"
    assert second["hostname"] == "api-slow.test"
    assert second["resolved_addresses"] == ["127.0.0.1"]
    assert second["approved_addresses"] == ["127.0.0.1"]
    assert second["connected_peer"] == f"127.0.0.1:{client._http.port}"
    assert second["request_sent"] is True
    assert second["status_code"] is None
    assert second["error"] and "超时" in second["error"]
    assert "不能判定为可达" in body["summary"] or "未收到完整响应" in body["summary"]

    # 第二跳目标确实收到了探测请求
    new_requests = client._http.requests[before:]
    assert any(req["host"] == "api-slow.test" for req in new_requests)


def test_overall_timeout_not_connected_reports_no_send(timeout_client):
    """解析阶段超时：未连接不得伪造连接地址，未发送不得标记为已发送。"""
    client = timeout_client
    # 让 DNS 静默丢包（解析器自身超时 2s > 总超时 0.6s）
    client._dns.datagram_received = lambda data, addr: None  # type: ignore[method-assign]

    r = client.post("/api/v1/probe", json={"url": "http://api-slowdns.test/"})

    assert r.status_code == 408
    body = r.json()["detail"]
    assert body["timeout_hop"] == 1
    hop = body["hops"][-1]
    assert hop["outcome"] == "timeout"
    assert hop["resolved_addresses"] == []
    assert hop["approved_addresses"] == []
    assert hop["connected_peer"] is None
    assert hop["request_sent"] is False
    assert hop["status_code"] is None


def test_incomplete_response_is_not_reported_reachable(client):
    """对端在响应头完整前断开：不得判为 ok/可达。"""
    import socket
    import threading

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def run():
        conn, _ = server.accept()
        conn.recv(65536)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Len")  # 半截头部后关闭
        conn.close()
        server.close()

    threading.Thread(target=run, daemon=True).start()
    client._dns.zones = {"api-truncated.test": ["127.0.0.1"]}

    r = client.post(
        "/api/v1/probe", json={"url": f"http://api-truncated.test:{port}/"}
    )

    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "error"
    hop = body["hops"][-1]
    assert hop["outcome"] == "error"
    assert hop["status_code"] is None
    assert "不完整" in hop["error"]
