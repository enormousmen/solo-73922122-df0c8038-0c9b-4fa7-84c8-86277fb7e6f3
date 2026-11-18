"""生成演示用 PKI：

* demo CA（自签名根证书 + 私钥）；
* targets 服务器证书（由 demo CA 签发，SAN 覆盖全部演示域名与目标 IP）；
* 合并 CA bundle（系统信任库 + demo CA），探测服务据此验证 HTTPS，
  既信任演示证书，也保留对真实公网证书的信任。

容器每次启动幂等执行；文件已存在且 KEY_REGEN 未置位时跳过。
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_DIR_DEFAULT = Path(os.getenv("CERT_DIR", "/app/certs"))
DAYS = int(os.getenv("CERT_DAYS", "3650"))

DEMO_NAMES = [
    "allowed.demo.test",
    "www.allowed.demo.test",
    "https.allowed.demo.test",
    "redirect-ok.demo.test",
    "redirect-final.demo.test",
    "forbidden.demo.test",
    "swapped.demo.test",
    "multi-a.demo.test",
    "loop1.demo.test",
    "loop2.demo.test",
    "loop3.demo.test",
    "loop4.demo.test",
]
DEMO_IPS = ["172.31.10.10", "172.31.20.10"]


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)


def main() -> None:
    cert_dir = Path(os.getenv("CERT_DIR", str(CERT_DIR_DEFAULT)))
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_cert_path = cert_dir / "demo-ca.crt.pem"
    ca_key_path = cert_dir / "demo-ca.key.pem"
    srv_cert_path = cert_dir / "targets.fullchain.pem"
    srv_key_path = cert_dir / "targets.key.pem"
    bundle_path = cert_dir / "combined-ca-bundle.pem"
    CERT_DIR = cert_dir

    if ca_cert_path.exists() and srv_cert_path.exists() and not os.getenv("KEY_REGEN"):
        print("[certinit] 证书已存在，跳过生成", flush=True)
        _build_bundle(ca_cert_path, bundle_path)
        return

    now = datetime.datetime.now(datetime.timezone.utc)
    # --- CA ---
    ca_key = _key()
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Egress Probe Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Egress Probe Demo CA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=DAYS))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(ca_key_path, ca_key)

    # --- 服务器证书 ---
    srv_key = _key()
    srv_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Egress Probe Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, "allowed.demo.test"),
        ]
    )
    san = x509.SubjectAlternativeName(
        [x509.DNSName(n) for n in DEMO_NAMES]
        + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in DEMO_IPS]
    )
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(san, critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    # fullchain = 服务器证书 + CA 证书
    srv_cert_path.write_bytes(
        srv_cert.public_bytes(serialization.Encoding.PEM)
        + ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    _write_key(srv_key_path, srv_key)
    _build_bundle(ca_cert_path, bundle_path)
    print(
        f"[certinit] 已生成 demo CA、服务器证书（SAN: {len(DEMO_NAMES)} 个 DNS 名, "
        f"{len(DEMO_IPS)} 个 IP）与合并 CA bundle",
        flush=True,
    )


def _build_bundle(ca_cert_path: Path, bundle_path: Path) -> None:
    parts: list[bytes] = []
    system_ca = ssl.get_default_verify_paths().cafile
    if system_ca and Path(system_ca).is_file():
        parts.append(Path(system_ca).read_bytes())
    parts.append(ca_cert_path.read_bytes())
    bundle_path.write_bytes(b"".join(parts))
    print(f"[certinit] 合并 CA bundle 已写入 {bundle_path}", flush=True)


if __name__ == "__main__":
    main()
