#!/usr/bin/env python3
"""
Exports the versioned OpenAPI 3.1.0 specification for email-auth-gateway
to docs/openapi.json and docs/openapi.yaml.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from webhook_receiver.app import app
DOCS_DIR = ROOT_DIR / "docs"


def export_openapi() -> None:
    schema = app.openapi()
    schema["info"]["version"] = "1.0.0"
    schema["info"]["title"] = "email-auth-gateway REST & Webhook API"
    schema["info"]["description"] = (
        "Enterprise Email Security and Authentication Gateway API specification.\n\n"
        "Provides endpoints for inbound mail ingestion (SendGrid, Mailgun, AWS SES, M365, "
        "Google Workspace), health monitoring, quarantine operations, multi-tenant administration, "
        "threat intelligence feeds, and SOC analytics."
    )
    schema["servers"] = [
        {"url": "/", "description": "Current Environment Gateway Server"},
        {"url": "http://localhost:8000", "description": "Local Development Server"},
        {"url": "https://email-security.example.com", "description": "Production Security Gateway"},
    ]

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = DOCS_DIR / "openapi.json"
    yaml_path = DOCS_DIR / "openapi.yaml"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)

    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(schema, f, sort_keys=False, default_flow_style=False)

    print(f"✓ Exported OpenAPI JSON to: {json_path}")
    print(f"✓ Exported OpenAPI YAML to: {yaml_path}")


if __name__ == "__main__":
    export_openapi()
