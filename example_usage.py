"""
Standalone demo of the auth-check stage.

In production this is the function you'd call from your inbound webhook
handler (SendGrid Inbound Parse / Mailgun Routes / SES + SNS all hand you
roughly: raw MIME bytes, the connecting/relay IP, and the envelope sender --
exactly the three inputs run_auth_checks() needs). This script just fakes
that payload from a local .eml file so you can test the module standalone.

Usage:
    python3 example_usage.py path/to/message.eml <client_ip> <envelope_from>

Example:
    python3 example_usage.py sample.eml 209.85.220.41 bounce@sendgrid.net
"""
from __future__ import annotations

import json
import sys

from auth_checker import run_auth_checks


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 1

    eml_path, client_ip, envelope_from = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(eml_path, "rb") as f:
        raw_message = f.read()

    verdict = run_auth_checks(raw_message, client_ip=client_ip, envelope_from=envelope_from)

    print(json.dumps(verdict.as_dict(), indent=2))

    # This is the shape Step 3 (the risk-score decision engine) consumes:
    #   verdict.score_delta  -> add straight into the cumulative message score
    #   verdict.reasons      -> human-readable audit trail for why
    if verdict.score_delta >= 70:
        print("\n-> would be diverted to quarantine (score contribution >= 70)")
    elif verdict.score_delta >= 30:
        print("\n-> would get a [WARNING: SUSPICIOUS] subject prefix (score contribution 30-69)")
    else:
        print("\n-> auth checks clean, forwarding as-is")

    return 0


if __name__ == "__main__":
    sys.exit(main())
