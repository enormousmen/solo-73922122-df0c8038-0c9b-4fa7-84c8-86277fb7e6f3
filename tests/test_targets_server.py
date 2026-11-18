"""演示目标服务（app/targets）的可控慢响应端点测试。

用真实 uvicorn 监听随机端口，验证：
* ``/slow`` 收到请求会被记录（说明第二跳确实到达目标）；
* ``mode=headers`` 只发响应头、不结束响应；
* ``/slow`` 在 delay 结束后正常返回；
* ``/redirect-slow`` 首跳 302 指向慢目标。
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
import uvicorn

from app.targets.server import app


@pytest.fixture()
async def target_base():
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.02)
    assert server.started
    sock = server.servers[0].sockets[0]
    port = sock.getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


async def test_redirect_slow_points_at_slow_target(target_base):
    async with httpx.AsyncClient(base_url=target_base) as client:
        r = await client.get("/redirect-slow?delay=30&mode=hang")
    assert r.status_code == 302
    location = r.headers["location"]
    assert location.startswith("http://slow.demo.test")
    assert "/slow?" in location
    assert "delay=30" in location and "mode=hang" in location


async def test_slow_hang_hold_then_responds(target_base):
    # delay 很短：应收到完整 200，且请求被记录（记录中带 slow_mode）
    async with httpx.AsyncClient(base_url=target_base) as client:
        r = await client.get("/slow?delay=0.05&mode=hang", timeout=5.0)
    assert r.status_code == 200
    assert b"slow target completed" in r.content

    from app.targets.server import RECENT_REQUESTS

    assert any(e.get("path") == "/slow" for e in RECENT_REQUESTS)
    assert RECENT_REQUESTS[0]["slow_mode"] == "hang"


async def test_slow_headers_partial_response_does_not_complete(target_base):
    async with httpx.AsyncClient(base_url=target_base) as client:
        with pytest.raises((httpx.ReadTimeout, httpx.RemoteProtocolError)):
            await client.get("/slow?delay=1.0&mode=headers", timeout=0.3)


async def test_slow_request_is_recorded_for_forensics(target_base):
    async with httpx.AsyncClient(base_url=target_base) as client:
        with pytest.raises(httpx.ReadTimeout):
            await client.get("/slow?delay=2&mode=hang", timeout=0.3)
    from app.targets.server import RECENT_REQUESTS

    entry = RECENT_REQUESTS[0]
    assert entry["path"] == "/slow"
    assert entry["slow_mode"] == "hang"
    assert entry["user_agent"]  # 真实请求头被记录
