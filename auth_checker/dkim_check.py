"""
DKIM verification.

Named dkim_check.py (not dkim.py) so it doesn't shadow the `dkim` package
this module imports from -- an easy footgun if you ever run this file
directly instead of importing it.

dkimpy does the actual crypto + DNS-key-fetch; this module just:
  - walks every DKIM-Signature header present (a message can be multi-signed)
  - returns the first one that verifies, since DMARC only needs one aligned pass
  - normalizes failures/DNS errors into our DKIMResult type
"""
from __future__ import annotations

import dkim as _dkimpy

from .models import DKIMResult, DKIMResultCode


def _count_signatures(raw_message: bytes) -> int:
    # set_message() (called from __init__) parses headers eagerly, so this
    # is available without triggering any DNS lookups or crypto work.
    d = _dkimpy.DKIM(raw_message)
    sigs = [h for (h, v) in d.headers if h.lower() == b"dkim-signature"]
    return len(sigs)


def check_dkim(raw_message: bytes, dnsfunc=None) -> DKIMResult:
    """
    raw_message: the full RFC 5322 message including headers, as bytes,
    UNMODIFIED since signing (any relay that rewrites headers/body breaks this --
    which is exactly the case DKIM exists to catch).

    dnsfunc: optional override for dkimpy's TXT lookup function, matching
    dkimpy's `dkim.get_txt` signature. Mainly here so tests can inject a
    fake public-key record instead of hitting real DNS.
    """
    try:
        sig_count = _count_signatures(raw_message)
    except Exception as exc:  # malformed message entirely
        return DKIMResult(code=DKIMResultCode.PERMERROR, explanation=f"could not parse message: {exc}")

    if sig_count == 0:
        return DKIMResult(code=DKIMResultCode.NONE, explanation="no DKIM-Signature header present")

    last_error = ""
    for idx in range(sig_count):
        d = _dkimpy.DKIM(raw_message)
        try:
            ok = d.verify(idx=idx, **({"dnsfunc": dnsfunc} if dnsfunc else {}))
        except _dkimpy.DnsTimeoutError as exc:
            last_error = str(exc)
            continue  # try the next signature; report temperror only if ALL fail this way
        except (_dkimpy.ValidationError, _dkimpy.MessageFormatError, _dkimpy.KeyFormatError,
                _dkimpy.UnparsableKeyError, _dkimpy.UnknownKeyTypeError) as exc:
            last_error = str(exc)
            continue
        except _dkimpy.DKIMException as exc:
            last_error = str(exc)
            continue

        domain = getattr(d, "domain", b"") or b""
        selector = getattr(d, "selector", b"") or b""
        if ok:
            return DKIMResult(
                code=DKIMResultCode.PASS,
                signing_domain=domain.decode(errors="replace"),
                selector=selector.decode(errors="replace"),
                explanation=f"valid signature from d={domain.decode(errors='replace')}",
            )
        last_error = f"signature {idx} (d={domain.decode(errors='replace')}) did not verify"

    return DKIMResult(code=DKIMResultCode.FAIL, explanation=last_error or "no signature verified")
