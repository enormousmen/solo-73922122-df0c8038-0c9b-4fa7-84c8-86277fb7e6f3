"""面向已批准 IPv4 地址的低层连接。

关键约束：
* ``open_connection`` 的 remote 永远是策略已批准的 IP 字面量，运行时
  不会再次解析 DNS —— 因此“检查后 DNS 换址”无法把连接带进未获准网段；
* HTTPS 使用 ``server_hostname=原域名`` 建立 SNI 并按原域名验证证书，
  ``check_hostname=True`` 且使用受信 CA 集合，调用方无法关闭校验。
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import dataclass

from .policy import PolicyError


@dataclass
class TlsInfo:
    version: str
    cipher: str
    subject: str
    san: list[str]
    peer_cert_subject: str


async def open_tcp(
    approved_ip: ipaddress.IPv4Address,
    port: int,
    connect_timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
    """打开到指定已批准 IP 的裸 TCP 连接，返回 (reader, writer, peer)。"""
    peer = f"{approved_ip}:{port}"
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(approved_ip), port),
            timeout=connect_timeout,
        )
    except asyncio.TimeoutError as exc:
        raise PolicyError(f"TCP 连接超时: {peer}") from exc
    except OSError as exc:
        raise PolicyError(f"TCP 连接失败: {peer} ({exc.strerror or exc})") from exc
    return reader, writer, peer


def build_ssl_context(ca_bundle: str | None) -> ssl.SSLContext:
    """构造强制校验的 TLS 上下文。

    ca_bundle 为 None 时使用系统信任库；否则使用指定的 CA 合并文件
    （演示环境把测试 CA 与系统 CA 合并，既信任测试证书又保留公网信任）。
    """
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=ca_bundle,
    )
    ctx.check_hostname = True  # 显式固定：按原域名校验
    ctx.verify_mode = ssl.CERT_REQUIRED  # 显式固定：必须校验证书
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


async def start_tls(
    writer: asyncio.StreamWriter,
    reader: asyncio.StreamReader,
    hostname: str,
    context: ssl.SSLContext,
    handshake_timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, TlsInfo]:
    try:
        # Python 3.11 兼容路径：在已有传输上启动 TLS
        await asyncio.wait_for(
            writer.start_tls(context, server_hostname=hostname),
            timeout=handshake_timeout,
        )
    except asyncio.TimeoutError as exc:
        raise PolicyError(f"TLS 握手超时（域名 {hostname}）") from exc
    except ssl.SSLCertVerificationError as exc:
        # 证书/主机名校验失败：明确告知，且不提供任何“跳过校验”的选项
        raise PolicyError(
            f"TLS 证书校验失败（按原域名 {hostname!r} 验证，未关闭校验）: "
            f"{exc.verify_message or exc}"
        ) from exc
    except ssl.SSLError as exc:
        raise PolicyError(f"TLS 握手失败: {exc}") from exc
    except OSError as exc:
        raise PolicyError(f"TLS 握手 IO 错误: {exc}") from exc

    # start_tls 会把底层传输替换为 TLS 传输，reader/writer 原地生效
    ssl_obj = writer.get_extra_info("ssl_object")
    if ssl_obj is None:
        raise PolicyError("TLS 启动后未取得 SSL 对象")
    cert = ssl_obj.getpeercert()
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    subject = _cert_name(cert.get("subject"))
    info = TlsInfo(
        version=ssl_obj.version() or "unknown",
        cipher=(ssl_obj.cipher() or ("unknown",))[0],
        subject=subject,
        san=sans,
        peer_cert_subject=subject,
    )
    return reader, writer, info


def _cert_name(rdn_sequence) -> str:
    if not rdn_sequence:
        return ""
    parts: list[str] = []
    for rdn in rdn_sequence:
        parts.extend(f"{k}={v}" for k, v in rdn)
    return ", ".join(parts)
