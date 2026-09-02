import ssl
import pytest
from security.mtls import MTLSContextBuilder, MTLSError, generate_self_signed_cert_pair


def test_generate_cert_pair_and_build_contexts():
    ca_path, srv_cert, srv_key, cli_cert, cli_key = generate_self_signed_cert_pair("localhost")

    # Build server context
    srv_ctx = MTLSContextBuilder.build_server_context(
        cert_file=srv_cert,
        key_file=srv_key,
        ca_file=ca_path,
        require_client_cert=True,
    )
    assert isinstance(srv_ctx, ssl.SSLContext)
    assert srv_ctx.verify_mode == ssl.CERT_REQUIRED

    # Build client context
    cli_ctx = MTLSContextBuilder.build_client_context(
        cert_file=cli_cert,
        key_file=cli_key,
        ca_file=ca_path,
        check_hostname=False,
    )
    assert isinstance(cli_ctx, ssl.SSLContext)
    assert cli_ctx.verify_mode == ssl.CERT_REQUIRED


def test_mtls_missing_files_error():
    with pytest.raises(MTLSError):
        MTLSContextBuilder.build_server_context("/missing/cert.pem", "/missing/key.pem", "/missing/ca.pem")
