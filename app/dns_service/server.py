"""本地演示 DNS 服务（UDP/53 + 控制面 HTTP/8053）。

解析数据按“场景 profile”组织，可通过 HTTP 控制面随时热切换，
用于演示“检查后换址”（DNS rebinding 类场景）：
  * profile=allowed 时域名解析到允许网段的目标；
  * 切换到 swapped 后同名域名解析到禁止网段，探测必须在连接前拦截；
  * profile=mixed 时一次应答同时包含允许与禁止地址，整体拒绝。

只实现 A 记录；未知域名返回 NXDOMAIN；非 A 查询返回 SERVFAIL。
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from ..probe import dns_wire

PROFILES_DIR = Path(os.getenv("DNS_PROFILES_DIR", "/app/dns-profiles"))
STATE_FILE = Path(os.getenv("DNS_STATE_FILE", "/tmp/dns-state/profile"))
CONTROL_PORT = int(os.getenv("DNS_CONTROL_PORT", "8053"))


class ProfileStore:
    def __init__(self) -> None:
        self._profiles: dict[str, dict[str, list[str]]] = {}
        self._active = ""
        self._lock = asyncio.Lock()
        self._load()
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        saved = STATE_FILE.read_text().strip() if STATE_FILE.exists() else ""
        self._active = saved if saved in self._profiles else next(iter(self._profiles))
        STATE_FILE.write_text(self._active)

    def _load(self) -> None:
        for path in sorted(PROFILES_DIR.glob("*.json")):
            data = json.loads(path.read_text())
            name = data["profile"]
            zones = {k.lower(): list(v) for k, v in data["zones"].items()}
            self._profiles[name] = zones

    @property
    def active(self) -> str:
        return self._active

    def list_profiles(self) -> dict:
        return {name: dict(zones) for name, zones in self._profiles.items()}

    def lookup(self, qname: str) -> tuple[int, list[str]]:
        qname = qname.lower().rstrip(".")
        zones = self._profiles[self._active]
        if qname in zones:
            return dns_wire.RCODE_OK, zones[qname]
        # 支持通配后缀（如 *.demo.test）
        for suffix, ips in zones.items():
            if suffix.startswith("*.") and qname.endswith(suffix[1:]):
                return dns_wire.RCODE_OK, ips
        return dns_wire.RCODE_NAME_ERROR, []

    async def switch(self, name: str) -> bool:
        async with self._lock:
            if name not in self._profiles:
                return False
            self._active = name
            STATE_FILE.write_text(name)
            return True


class DnsUdpServer(asyncio.DatagramProtocol):
    def __init__(self, store: ProfileStore) -> None:
        self._store = store
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def connection_lost(self, exc) -> None:  # noqa: ANN001
        self._transport = None

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        try:
            msg = dns_wire.parse_message(data, require_qr=False)
            question = msg.questions[0] if msg.questions else None
            if question is None or question.qtype != dns_wire.TYPE_A:
                reply = dns_wire.build_response(
                    msg.qid, question, rcode=dns_wire.RCODE_SERVFAIL
                )
            else:
                rcode, ips = self._store.lookup(question.qname)
                reply = dns_wire.build_response(
                    msg.qid, question, rcode=rcode, answers=ips
                )
        except (dns_wire.DnsProtocolError, IndexError):
            reply = b""
        if reply and self._transport is not None:
            self._transport.sendto(reply, addr)


async def _control_app(store: ProfileStore) -> "asyncio.base_events.Server":
    from aiohttp import web  # 延迟导入，仅 DNS 服务需要

    async def get_profiles(_request):
        return web.json_response(
            {"active": store.active, "profiles": store.list_profiles()}
        )

    async def switch(request):
        body = await request.json()
        name = str(body.get("profile", ""))
        if await store.switch(name):
            return web.json_response(
                {"active": store.active, "profiles": store.list_profiles()}
            )
        return web.json_response(
            {"error": f"未知 profile: {name!r}",
             "available": list(store.list_profiles())},
            status=404,
        )

    app = web.Application()
    app.router.add_get("/profiles", get_profiles)
    app.router.add_post("/profiles/switch", switch)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", CONTROL_PORT)
    await site.start()
    return site


async def serve() -> None:
    store = ProfileStore()
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: DnsUdpServer(store),
        local_addr=("0.0.0.0", 53),
    )
    await _control_app(store)
    print(
        f"[dns-service] UDP/53 已启动，初始 profile={store.active!r}，"
        f"控制面 HTTP/{CONTROL_PORT}",
        flush=True,
    )
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(serve())
