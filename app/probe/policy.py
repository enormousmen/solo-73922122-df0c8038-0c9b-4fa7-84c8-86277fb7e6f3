"""出站地址策略：IPv4 白名单（CIDR）校验。

所有连接决策都集中在本模块，保证：
* 仅允许 IPv4（IPv6、主机名等一律拒绝）；
* 启动时配置允许的 CIDR 白名单；
* 一次 DNS 返回的 *全部* 地址都必须获准，任一地址在禁区即整体拒绝；
* 拒绝决策在建立任何 socket 之前完成，被拒目标不会收到探测请求。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

ALLOWED_SCHEMES = frozenset({"http", "https"})


class PolicyError(ValueError):
    """策略拒绝或目标不可用时抛出，message 即面向调用方的拒绝原因。"""


@dataclass(frozen=True)
class AddressPolicy:
    """IPv4 CIDR 白名单策略。"""

    allowed_nets: tuple[ipaddress.IPv4Network, ...]

    @classmethod
    def from_cidrs(cls, cidrs: list[str]) -> "AddressPolicy":
        nets: list[ipaddress.IPv4Network] = []
        for raw in cidrs:
            raw = raw.strip()
            if not raw:
                continue
            try:
                net = ipaddress.ip_network(raw, strict=True)
            except ValueError as exc:
                raise PolicyError(f"非法 CIDR 配置: {raw!r} ({exc})") from exc
            if net.version != 4:
                raise PolicyError(f"仅支持 IPv4 CIDR，拒绝 IPv6 网段: {raw!r}")
            nets.append(net)
        return cls(tuple(nets))

    def check_ip(self, ip: str) -> ipaddress.IPv4Address:
        """校验单个地址字面量，返回解析后的 IPv4Address；否则抛 PolicyError。"""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise PolicyError(f"非法 IP 地址: {ip!r}") from exc
        if addr.version != 4:
            raise PolicyError(f"仅支持 IPv4，拒绝 IPv6 地址: {ip}")
        if not any(addr in net for net in self.allowed_nets):
            raise PolicyError(
                f"目标地址 {ip} 不在允许的出口白名单 "
                f"({', '.join(str(n) for n in self.allowed_nets)}) 内"
            )
        return addr

    def check_resolved(self, ips: list[str]) -> list[ipaddress.IPv4Address]:
        """校验一次 DNS 查询得到的全部地址。

        全部地址均获准才返回；任一地址在禁区即整体拒绝（不返回部分结果，
        调用方因此不会有机会只连接“获准的那一个”）。
        """
        if not ips:
            raise PolicyError("DNS 未返回任何 IPv4 地址")
        approved: list[ipaddress.IPv4Address] = []
        denied: list[str] = []
        non_ipv4: list[str] = []
        for ip in ips:
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                denied.append(ip)
                continue
            if parsed.version != 4:
                non_ipv4.append(ip)
                continue
            try:
                approved.append(self.check_ip(ip))
            except PolicyError:
                denied.append(ip)
        if non_ipv4:
            raise PolicyError(
                "仅支持 IPv4，拒绝 IPv6/非 IPv4 地址: " + ", ".join(non_ipv4)
            )
        if denied:
            raise PolicyError(
                "解析结果包含未获准网段的地址: "
                + ", ".join(denied)
                + "；按白名单策略整体拒绝（全部解析地址均获准才可连接）"
            )
        return approved


def parse_target(url: str) -> tuple[str, str, int | None, str | None, str]:
    """解析并初步校验用户提交的 URL。

    返回 (scheme, hostname, port, userinfo, raw_url)。
    仅做与连接无关的静态检查；网段检查由 AddressPolicy 完成。
    """
    if not isinstance(url, str) or not url.strip():
        raise PolicyError("URL 为空")
    raw = url.strip()
    if len(raw) > 2048:
        raise PolicyError("URL 过长（上限 2048 字符）")
    # urllib 对 "http://[::1]/" 等可正确解析；对 "http://127.1" 也能拆出主机。
    parts = _urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise PolicyError(
            f"不支持的 URL scheme: {parts.scheme!r}，仅允许 http/https"
        )
    if parts.username is not None or parts.password is not None:
        raise PolicyError("URL 中禁止携带用户名/密码（userinfo）")
    host = parts.hostname
    if not host:
        raise PolicyError("URL 缺少主机名")
    if " " in host:
        raise PolicyError(f"主机名非法: {host!r}")
    port = parts.port  # 非法端口会抛 ValueError，统一转成 PolicyError
    return scheme, host, port, parts.username, raw


def _urlsplit(raw: str):
    from urllib.parse import urlsplit

    try:
        return urlsplit(raw)
    except ValueError as exc:
        raise PolicyError(f"URL 解析失败: {exc}") from exc


def is_ip_literal(host: str) -> bool:
    """主机名是否为 IP 字面量（含 IPv6 方括号形式，urlsplit 已去括号）。"""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
