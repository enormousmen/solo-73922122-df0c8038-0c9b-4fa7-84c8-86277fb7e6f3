"""探测服务启动配置（全部来自环境变量，启动时校验，非法即拒绝启动）。"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .policy import AddressPolicy, PolicyError


@dataclass(frozen=True)
class Settings:
    policy: AddressPolicy
    dns_server: str
    dns_port: int
    dns_timeout: float
    dns_retries: int
    ca_bundle: str | None
    connect_timeout: float
    read_timeout: float
    tls_timeout: float
    max_redirects: int
    max_concurrency: int
    overall_timeout: float

    @property
    def allowed_cidrs(self) -> list[str]:
        return [str(n) for n in self.policy.allowed_nets]


def load_settings() -> Settings:
    raw_cidrs = os.getenv("ALLOWED_CIDRS", "")
    cidrs = [c.strip() for c in raw_cidrs.split(",") if c.strip()]
    try:
        policy = AddressPolicy.from_cidrs(cidrs)
    except PolicyError as exc:
        raise SystemExit(f"启动失败: {exc}") from exc

    max_redirects = int(os.getenv("MAX_REDIRECTS", "3"))
    if max_redirects < 0 or max_redirects > 3:
        raise SystemExit("启动失败: MAX_REDIRECTS 仅允许 0..3（需求上限为 3 次跳转）")

    ca_bundle = os.getenv("CA_BUNDLE", "").strip() or None
    if ca_bundle is not None and not os.path.isfile(ca_bundle):
        raise SystemExit(f"启动失败: CA_BUNDLE 文件不存在: {ca_bundle}")

    return Settings(
        policy=policy,
        dns_server=os.getenv("DNS_SERVER", "127.0.0.1").strip(),
        dns_port=int(os.getenv("DNS_PORT", "53")),
        dns_timeout=float(os.getenv("DNS_TIMEOUT", "3.0")),
        dns_retries=int(os.getenv("DNS_RETRIES", "1")),
        ca_bundle=ca_bundle,
        connect_timeout=float(os.getenv("CONNECT_TIMEOUT", "5.0")),
        read_timeout=float(os.getenv("READ_TIMEOUT", "10.0")),
        tls_timeout=float(os.getenv("TLS_TIMEOUT", "8.0")),
        max_redirects=max_redirects,
        max_concurrency=int(os.getenv("MAX_CONCURRENCY", "64")),
        overall_timeout=float(os.getenv("PROBE_OVERALL_TIMEOUT", "30.0")),
    )
