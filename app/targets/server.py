"""演示用目标 Web 服务。

同一进程监听：
* 8080/tcp HTTP（允许目标 172.31.10.10 与禁止目标 172.31.20.10 都运行本服务）；
* 8443/tcp HTTPS（使用受信演示 CA 签发的证书，含全部演示域名 SAN）。

按 Host 头提供不同路径行为：正常 200、跳转至允许/禁止目标、跳转链、
回显请求来源等。``/_requests`` 记录本进程收到的请求，供演示脚本验证
“被策略拒绝的目标从未收到探测请求”。
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from urllib.parse import parse_qs, urlencode

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

CERT_DIR = os.getenv("CERT_DIR", "/app/certs")
# 慢目标默认挂起时长（秒）；可被请求参数 delay 覆盖，便于“可控”演示。
SLOW_HANG_SECONDS = float(os.getenv("SLOW_HANG_SECONDS", "60"))
MAX_SLOW_SECONDS = float(os.getenv("MAX_SLOW_SECONDS", "120"))
# 首跳跳转到慢目标时使用的端口（compose 内为标准 80）
SLOW_REDIRECT_PORT = os.getenv("SLOW_REDIRECT_PORT", "80")
RECENT_REQUESTS: deque[dict] = deque(maxlen=200)

app = FastAPI(title="demo-targets", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def record_requests(request: Request, call_next):
    RECENT_REQUESTS.appendleft(
        {
            "ts": round(time.time(), 3),
            "method": request.method,
            "host": request.headers.get("host"),
            "path": request.url.path,
            "peer": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
    )
    return await call_next(request)


@app.get("/")
async def root(request: Request):
    return JSONResponse(
        {
            "service": "demo-targets",
            "host": request.headers.get("host"),
            "peer": request.client.host if request.client else None,
            "tls": request.url.scheme == "https",
            "message": "目标可达",
        }
    )


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


@app.get("/_requests")
async def list_requests():
    return JSONResponse(list(RECENT_REQUESTS))


@app.get("/redirect-allowed")
async def redirect_allowed():
    return RedirectResponse(url="http://redirect-final.demo.test/final", status_code=302)


@app.get("/redirect-https")
async def redirect_https():
    return RedirectResponse(
        url="https://https.allowed.demo.test/secure", status_code=302
    )


@app.get("/redirect-forbidden")
async def redirect_forbidden():
    # 跳到禁止网段的目标：探测方必须在第二跳解析校验时拦截
    return RedirectResponse(url="http://forbidden.demo.test/secret", status_code=302)


@app.get("/redirect-scheme")
async def redirect_scheme():
    # 跳到非 HTTP(S) 协议：探测方应拒绝
    return RedirectResponse(url="file:///etc/passwd", status_code=302)


@app.get("/redirect-slow")
async def redirect_slow(
    delay: float = SLOW_HANG_SECONDS,
    mode: str = "hang",
):
    """首跳返回 302，第二跳指向“收下请求但不给完整响应”的慢目标。

    这正是值班员遇到的场景：首跳 302、第二跳请求已发出却无响应，
    最终接口返回 408 —— 此时 408 必须能指出第二跳的实际进度。
    """
    delay = min(max(delay, 0.0), MAX_SLOW_SECONDS)
    if mode not in {"hang", "headers"}:
        mode = "hang"
    query = urlencode({"delay": delay, "mode": mode})
    location = f"http://slow.demo.test:{SLOW_REDIRECT_PORT}/slow?{query}"
    return RedirectResponse(url=location, status_code=302)


@app.get("/final")
async def final():
    return JSONResponse({"message": "跳转链终点，可达"})


@app.get("/secure")
async def secure(request: Request):
    return JSONResponse(
        {
            "message": "HTTPS 目标可达，证书按原域名验证通过",
            "host": request.headers.get("host"),
            "scheme": request.url.scheme,
        }
    )


# 跳转链：loop1/loop/1 -> loop2/loop/2 -> loop3/loop/3 -> loop4/loop/4 -> loop1 …
@app.get("/loop/{n}")
async def loop_chain(n: int):
    next_n = 1 if n >= 4 else n + 1
    return RedirectResponse(
        url=f"http://loop{next_n}.demo.test/loop/{next_n}",
        status_code=307,
    )


@app.get("/secret")
async def secret():
    return JSONResponse({"message": "禁止网段目标不应被任何探测请求到达"})


class SlowTargetMiddleware:
    """``/slow`` 的可控慢响应端点（纯 ASGI，绕开框架的完整响应生成）。

    * ``mode=hang``：完全收下请求后保持连接、不发任何字节，最终（delay 秒后）
      才返回 200 —— 探测端若在 delay 之前达到超时，必须报告超时而非可达；
    * ``mode=headers``：只发响应头（声称有 body）便挂起，迟到不发 body。

    该中间件位于最外层，因此 ``/_requests`` 的记录在此手动补上，便于验证
    “第二跳确实收到了探测请求”。
    """

    def __init__(self, app) -> None:  # noqa: ANN001
        self.app = app

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        if scope["type"] != "http" or scope["path"] != "/slow":
            await self.app(scope, receive, send)
            return

        query = {
            k: v[-1]
            for k, v in parse_qs(scope.get("query_string", b"").decode()).items()
        }
        try:
            delay = float(query.get("delay", SLOW_HANG_SECONDS))
        except ValueError:
            delay = SLOW_HANG_SECONDS
        delay = min(max(delay, 0.0), MAX_SLOW_SECONDS)
        mode = query.get("mode", "hang")
        if mode not in {"hang", "headers"}:
            mode = "hang"
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        client = scope.get("client") or (None, None)
        RECENT_REQUESTS.appendleft(
            {
                "ts": round(time.time(), 3),
                "method": scope.get("method"),
                "host": headers.get("host"),
                "path": scope["path"],
                "peer": client[0],
                "user_agent": headers.get("user-agent"),
                "slow_mode": mode,
                "slow_delay": delay,
            }
        )

        if mode == "headers":
            try:
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            (b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", b"64"),
                        ],
                    }
                )
                await asyncio.sleep(delay)  # 不发送 body
            except (OSError, RuntimeError):
                pass
            return
        # mode == "hang"：先静默挂起，超时窗口过去后才写出完整响应
        await asyncio.sleep(delay)
        body = b'{"message":"slow target completed after delay"}'
        try:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (b"connection", b"close"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
        except (OSError, RuntimeError):
            # 探测端已超时断开：慢目标的“迟到响应”写不出去属预期行为
            pass


app.add_middleware(SlowTargetMiddleware)


def _server_kwargs() -> dict:
    return {
        "app": app,
        "log_level": "warning",
        "access_log": False,
    }


async def _one_server(port: int, ssl_cert: str | None = None,
                      ssl_key: str | None = None) -> uvicorn.Server:
    cfg_kwargs = dict(host="0.0.0.0", port=port, **_server_kwargs())
    if ssl_cert and ssl_key:
        cfg_kwargs.update(ssl_certfile=ssl_cert, ssl_keyfile=ssl_key)
    server = uvicorn.Server(uvicorn.Config(**cfg_kwargs))
    # 直接返回由 gather 驱动；这里只构造，不阻塞
    return server


async def serve() -> None:
    # 同时监听标准端口（80/443，供跳转 URL 直接使用）与演示端口（8080/8443）。
    # 容器以 root 启动可绑定特权端口；本地非特权演示可经环境变量改为高位端口。
    http_ports = [int(p) for p in os.getenv("TARGET_HTTP_PORTS", "80,8080").split(",")]
    https_ports = [int(p) for p in os.getenv("TARGET_HTTPS_PORTS", "443,8443").split(",")]
    cert = f"{CERT_DIR}/targets.fullchain.pem"
    key = f"{CERT_DIR}/targets.key.pem"
    servers: list[uvicorn.Server] = []
    for p in http_ports:
        servers.append(await _one_server(p))
    for p in https_ports:
        servers.append(await _one_server(p, cert, key))
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    asyncio.run(serve())
