"""
Mutual TLS (mTLS) configuration and context builder for securing internal
communication between gateway components (webhook receiver, worker pool, admin API).
"""
from __future__ import annotations

import datetime
import os
import ssl
import tempfile
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class MTLSError(Exception):
    """Base exception for mTLS operations."""
    pass


class MTLSContextBuilder:
    """Helper to create SSL/TLS contexts for Mutual TLS (mTLS) communication."""

    @staticmethod
    def build_server_context(
        cert_file: str,
        key_file: str,
        ca_file: str,
        require_client_cert: bool = True,
    ) -> ssl.SSLContext:
        """Create SSL context for a server enforcing client certificate verification."""
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            raise MTLSError(f"Certificate or key file not found: {cert_file}, {key_file}")
        if not os.path.exists(ca_file):
            raise MTLSError(f"CA certificate file not found: {ca_file}")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        context.load_verify_locations(cafile=ca_file)

        if require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_OPTIONAL

        # Secure default TLS settings
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        return context

    @staticmethod
    def build_client_context(
        cert_file: str,
        key_file: str,
        ca_file: str,
        check_hostname: bool = True,
    ) -> ssl.SSLContext:
        """Create SSL context for a client presenting a client cert and verifying server cert."""
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            raise MTLSError(f"Client certificate or key file not found: {cert_file}, {key_file}")
        if not os.path.exists(ca_file):
            raise MTLSError(f"CA certificate file not found: {ca_file}")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        context.load_verify_locations(cafile=ca_file)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = check_hostname

        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        return context


def generate_self_signed_cert_pair(common_name: str = "localhost") -> Tuple[str, str, str, str, str]:
    """
    Utility function to generate a self-signed CA, server cert/key, and client cert/key
    stored in temporary files. Returns tuple of (ca_cert_path, server_cert_path, server_key_path, client_cert_path, client_key_path).
    """
    tmp_dir = tempfile.mkdtemp(prefix="mtls_keys_")

    # 1. Generate CA key & cert
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = ca_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EmailGateway Internal CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Internal Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = os.path.join(tmp_dir, "ca.crt")
    with open(ca_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    # Helper to generate entity cert
    def _gen_cert(name: str, alt_names: Optional[list[str]] = None):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EmailGateway Service"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        if alt_names:
            san_list = [x509.DNSName(n) for n in alt_names]
            builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

        cert = builder.sign(ca_key, hashes.SHA256())

        cert_path = os.path.join(tmp_dir, f"{name}.crt")
        key_path = os.path.join(tmp_dir, f"{name}.key")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        return cert_path, key_path

    srv_cert, srv_key = _gen_cert("server", alt_names=[common_name, "127.0.0.1"])
    cli_cert, cli_key = _gen_cert("client")

    return ca_path, srv_cert, srv_key, cli_cert, cli_key
