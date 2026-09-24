"""
Tests validating documentation completeness, OpenAPI spec validity, and configuration aliases.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pytest
import yaml

from config import Settings


ROOT_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT_DIR / "docs"


def test_openapi_spec_files_exist_and_are_valid():
    json_path = DOCS_DIR / "openapi.json"
    yaml_path = DOCS_DIR / "openapi.yaml"

    assert json_path.exists(), "docs/openapi.json must exist"
    assert yaml_path.exists(), "docs/openapi.yaml must exist"

    with open(json_path, "r", encoding="utf-8") as f:
        spec_json = json.load(f)

    with open(yaml_path, "r", encoding="utf-8") as f:
        spec_yaml = yaml.safe_load(f)

    assert spec_json["openapi"].startswith("3.")
    assert spec_json["info"]["version"] == "1.0.0"
    assert "paths" in spec_json

    # Check key endpoints are in the spec
    paths = spec_json["paths"]
    assert "/healthz" in paths
    assert "/readyz" in paths
    assert "/webhooks/sendgrid/inbound/{secret}" in paths

    # Validate json and yaml match
    assert spec_json["info"]["title"] == spec_yaml["info"]["title"]
    assert len(spec_json["paths"]) == len(spec_yaml["paths"])


def test_architecture_documentation_c4_diagrams():
    arch_md = DOCS_DIR / "architecture.md"
    assert arch_md.exists()
    content = arch_md.read_text(encoding="utf-8")

    # Verify C4 model sections
    assert "Level 1: System Context Diagram" in content
    assert "Level 2: Container Diagram" in content
    assert "Level 3: Component Diagram" in content
    assert "Level 4: Execution Sequence" in content
    assert "```mermaid" in content


def test_tenant_onboarding_guide():
    guide_md = DOCS_DIR / "tenant_onboarding.md"
    assert guide_md.exists()
    content = guide_md.read_text(encoding="utf-8")

    assert "New-Tenant Onboarding Guide" in content
    assert "Fernet" in content
    assert "SendGrid Inbound Parse" in content
    assert "Mailgun Inbound Routes" in content
    assert "ENABLE_TAG_ONLY_MODE" in content


def test_detection_changelog():
    changelog_md = DOCS_DIR / "detection_changelog.md"
    assert changelog_md.exists()
    content = changelog_md.read_text(encoding="utf-8")

    assert "Detection Logic & Scoring Matrix Changelog" in content
    assert "Version 1.4.0" in content
    assert "Quishing" in content
    assert "Polyglot" in content
    assert "Zero-Width Character" in content


def test_configuration_documentation_and_env_example():
    config_md = DOCS_DIR / "configuration.md"
    env_example = ROOT_DIR / ".env.example"

    assert config_md.exists()
    assert env_example.exists()

    cfg_text = config_md.read_text(encoding="utf-8")
    env_text = env_example.read_text(encoding="utf-8")

    # Verify external API links and sites are documented
    assert "https://www.virustotal.com/gui/my-apikey" in cfg_text
    assert "https://www.virustotal.com/gui/my-apikey" in env_text
    assert "https://console.cloud.google.com/apis/credentials" in cfg_text
    assert "https://console.cloud.google.com/apis/credentials" in env_text
    assert "https://portal.azure.com" in cfg_text
    assert "https://portal.azure.com" in env_text
    assert "https://app.mailgun.com/settings/api_keys" in cfg_text
    assert "https://app.sendgrid.com/settings/api_keys" in cfg_text

    # Verify CLI / shell generation commands are documented
    assert "secrets.token_urlsafe" in cfg_text
    assert "secrets.token_urlsafe" in env_text
    assert "Fernet.generate_key" in cfg_text
    assert "Fernet.generate_key" in env_text
    assert "docker run -d --name clamav" in cfg_text
    assert "docker run -d --name redis" in cfg_text


def test_settings_aliases_support():
    # Test that both long and short env var aliases populate settings
    os.environ["VIRUSTOTAL_API_KEY"] = "vt_test_key_alias"
    os.environ["VT_API_KEY"] = ""
    os.environ["SAFE_BROWSING_API_KEY"] = "gsb_test_key_alias"
    os.environ["GSB_API_KEY"] = ""
    os.environ["CLAMAV_HOST"] = "clamav.internal"
    os.environ["CLAMD_HOST"] = ""
    os.environ["ENCRYPTION_KEY"] = "fernet_test_key_alias"
    os.environ["RAW_MAIL_ENCRYPTION_KEY"] = ""

    try:
        s = Settings()
        assert s.vt_api_key == "vt_test_key_alias"
        assert s.gsb_api_key == "gsb_test_key_alias"
        assert s.clamd_host == "clamav.internal"
        assert s.raw_mail_encryption_key == "fernet_test_key_alias"
    finally:
        os.environ.pop("VIRUSTOTAL_API_KEY", None)
        os.environ.pop("VT_API_KEY", None)
        os.environ.pop("SAFE_BROWSING_API_KEY", None)
        os.environ.pop("GSB_API_KEY", None)
        os.environ.pop("CLAMAV_HOST", None)
        os.environ.pop("CLAMD_HOST", None)
        os.environ.pop("ENCRYPTION_KEY", None)
        os.environ.pop("RAW_MAIL_ENCRYPTION_KEY", None)
