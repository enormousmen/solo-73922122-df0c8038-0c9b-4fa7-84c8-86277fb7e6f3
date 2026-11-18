"""AddressPolicy / URL 解析单元测试。"""

import ipaddress

import pytest

from app.probe.policy import (
    AddressPolicy,
    PolicyError,
    is_ip_literal,
    parse_target,
)


@pytest.fixture()
def policy() -> AddressPolicy:
    return AddressPolicy.from_cidrs(["172.31.10.0/24", "10.0.0.0/8"])


class TestAddressPolicy:
    def test_allowed_ips(self, policy):
        assert policy.check_ip("172.31.10.10") == ipaddress.ip_address("172.31.10.10")
        assert policy.check_ip("10.255.0.1") == ipaddress.ip_address("10.255.0.1")

    @pytest.mark.parametrize("ip", ["172.31.20.10", "8.8.8.8", "127.0.0.1", "169.254.1.1"])
    def test_denied_ips(self, policy, ip):
        with pytest.raises(PolicyError, match="白名单"):
            policy.check_ip(ip)

    @pytest.mark.parametrize("ip", ["::1", "fe80::1", "2001:db8::1"])
    def test_ipv6_always_denied(self, policy, ip):
        with pytest.raises(PolicyError, match="IPv6"):
            policy.check_ip(ip)

    def test_all_resolved_must_be_approved(self, policy):
        # 混合应答：一个允许一个禁止 -> 整体拒绝
        with pytest.raises(PolicyError, match="整体拒绝"):
            policy.check_resolved(["172.31.10.10", "172.31.20.10"])
        # 全部允许 -> 通过
        approved = policy.check_resolved(["172.31.10.10", "172.31.10.11"])
        assert [str(a) for a in approved] == ["172.31.10.10", "172.31.10.11"]

    def test_empty_resolution_denied(self, policy):
        with pytest.raises(PolicyError, match="未返回任何 IPv4"):
            policy.check_resolved([])

    def test_no_partial_results_on_denial(self, policy):
        # 拒绝时不得返回部分获准地址，防止调用方挑一个连
        with pytest.raises(PolicyError):
            policy.check_resolved(["10.0.0.1", "8.8.8.8"])

    def test_config_rejects_ipv6_cidr(self):
        with pytest.raises(PolicyError, match="IPv6"):
            AddressPolicy.from_cidrs(["2001:db8::/32"])

    def test_config_rejects_bad_cidr(self):
        with pytest.raises(PolicyError, match="非法 CIDR"):
            AddressPolicy.from_cidrs(["not-a-cidr"])
        with pytest.raises(PolicyError, match="非法 CIDR"):
            AddressPolicy.from_cidrs(["172.31.10.0/33"])


class TestUrlParsing:
    @pytest.mark.parametrize("url", [
        "http://allowed.demo.test/",
        "https://allowed.demo.test:8443/secure",
        "http://172.31.10.10/x?y=1",
    ])
    def test_valid_urls(self, url):
        scheme, host, port, user, raw = parse_target(url)
        assert scheme in ("http", "https")
        assert host

    @pytest.mark.parametrize("url", [
        "ftp://allowed.demo.test/",
        "file:///etc/passwd",
        "gopher://x/",
        "",
        "   ",
    ])
    def test_bad_scheme_or_empty(self, url):
        with pytest.raises(PolicyError):
            parse_target(url)

    def test_userinfo_forbidden(self):
        with pytest.raises(PolicyError, match="userinfo"):
            parse_target("http://user:pass@allowed.demo.test/")

    def test_redirect_to_non_http_scheme_detected_later(self):
        from app.probe.http_probe import normalize_redirect

        with pytest.raises(PolicyError, match="非 HTTP"):
            normalize_redirect("http://a.test/", "file:///etc/passwd")

    def test_relative_redirect_supported(self):
        from app.probe.http_probe import normalize_redirect

        assert (
            normalize_redirect("http://a.test/x/y", "/z")
            == "http://a.test/z"
        )
        assert (
            normalize_redirect("http://a.test/x", "//b.test/z")
            == "http://b.test/z"
        )

    def test_is_ip_literal(self):
        assert is_ip_literal("172.31.10.10")
        assert is_ip_literal("::1")
        assert not is_ip_literal("demo.test")
