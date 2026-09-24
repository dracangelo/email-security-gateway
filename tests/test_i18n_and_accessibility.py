"""
Tests for Internationalization, Localization, and Accessibility (Task 20):
- Multi-language dictionary and keyword scanning
- Admin UI localization bundles (en, es, de, fr, ja, zh, pt)
- WCAG 2.1 AA accessibility features (skip-link, ARIA roles, keyboard navigation hooks)
- Timezone-aware timestamp conversion and metric aggregation
- Tenant-specific timezone preferences
"""
from __future__ import annotations

import time
from datetime import datetime, timezone as dt_timezone
import pytest
import zoneinfo

from admin_ui import (
    DashboardAnalyticsEngine,
    get_all_translations,
    get_translation,
    get_translations_bundle,
    render_admin_dashboard_html,
)
from content_analysis.multilang_keywords import detect_language, scan_multilang_keywords
from multi_tenancy import Tenant, TenantManager


def test_i18n_translation_bundles():
    translations = get_all_translations()
    assert "en" in translations
    assert "es" in translations
    assert "de" in translations
    assert "fr" in translations
    assert "ja" in translations
    assert "zh" in translations
    assert "pt" in translations

    # Test key translations
    assert get_translation("tab_dashboard", "en") == "Dashboard"
    assert get_translation("tab_dashboard", "es") == "Panel de Control"
    assert get_translation("tab_dashboard", "de") == "Übersicht"
    assert get_translation("tab_dashboard", "fr") == "Tableau de Bord"
    assert get_translation("tab_dashboard", "ja") == "ダッシュボード"
    assert get_translation("tab_dashboard", "zh") == "仪表板"
    assert get_translation("tab_dashboard", "pt") == "Painel de Controle"

    # Test fallback to English on unknown key or unknown language
    assert get_translation("tab_dashboard", "xx") == "Dashboard"
    assert get_translation("non_existent_key_xyz", "en") == "non_existent_key_xyz"

    # Test bundle retrieval
    bundle_de = get_translations_bundle("de")
    assert bundle_de["release_selected"] == "Ausgewählte freigeben"


def test_admin_ui_html_accessibility_and_localization():
    html = render_admin_dashboard_html()

    # Accessibility (WCAG 2.1 AA) checks
    assert 'class="skip-link"' in html
    assert 'href="#main-content"' in html
    assert 'role="tablist"' in html
    assert 'role="tab"' in html
    assert 'aria-selected="true"' in html
    assert 'role="tabpanel"' in html
    assert 'role="dialog"' in html
    assert 'aria-modal="true"' in html
    assert ':focus-visible' in html

    # Localization dropdown and data attributes
    assert 'id="lang-select"' in html
    assert 'data-i18n="brand"' in html
    assert 'data-i18n="tab_dashboard"' in html
    assert 'data-i18n-placeholder=' in html

    # Timezone dropdown
    assert 'id="tz-select"' in html
    assert 'value="UTC"' in html
    assert 'value="America/New_York"' in html
    assert 'value="Asia/Tokyo"' in html
    assert 'value="Europe/Berlin"' in html


def test_timezone_formatting_and_aggregation():
    analytics = DashboardAnalyticsEngine(quarantine_store=None)

    # 1. format_timestamp_tz
    # 2026-09-24 12:00:00 UTC
    dt_utc = datetime(2026, 9, 24, 12, 0, 0, tzinfo=dt_timezone.utc)
    ts_epoch = dt_utc.timestamp()

    formatted_utc = analytics.format_timestamp_tz(ts_epoch, "UTC")
    assert "2026-09-24 12:00:00 UTC" in formatted_utc

    # In New York (EDT, UTC-4), 12:00 UTC is 08:00 EDT
    formatted_ny = analytics.format_timestamp_tz(ts_epoch, "America/New_York")
    assert "2026-09-24 08:00:00 EDT" in formatted_ny

    # In Tokyo (JST, UTC+9), 12:00 UTC is 21:00 JST
    formatted_tokyo = analytics.format_timestamp_tz(ts_epoch, "Asia/Tokyo")
    assert "2026-09-24 21:00:00 JST" in formatted_tokyo

    # Fallback on invalid timezone name
    formatted_fallback = analytics.format_timestamp_tz(ts_epoch, "Invalid/Unknown_Zone")
    assert "2026-09-24 12:00:00 UTC" in formatted_fallback

    # 2. aggregate_metrics_by_timezone
    mock_records = [
        {"timestamp": ts_epoch, "total_score": 85, "sender": "bad@phish.com"},
        {"timestamp": ts_epoch + 3600, "total_score": 45, "sender": "warn@corp.com"},
        {"timestamp": ts_epoch + 7200, "total_score": 10, "sender": "clean@corp.com"},
    ]

    agg_ny = analytics.aggregate_metrics_by_timezone(mock_records, tz_name="America/New_York")
    assert agg_ny["timezone"] == "America/New_York"
    assert "daily_volume" in agg_ny
    assert "hourly_volume" in agg_ny
    assert "severity_by_hour" in agg_ny

    # In NY, the hours are 08:00, 09:00, 10:00
    assert "2026-09-24 08:00" in agg_ny["hourly_volume"]
    assert "2026-09-24 09:00" in agg_ny["hourly_volume"]
    assert "2026-09-24 10:00" in agg_ny["hourly_volume"]
    assert agg_ny["severity_by_hour"]["2026-09-24 08:00"]["high"] == 1


def test_tenant_timezone_configuration():
    manager = TenantManager()
    tenant = manager.create_tenant(
        tenant_id="tenant_apac",
        name="APAC Headquarters",
        domains=["apac.example.com"],
        timezone="Asia/Tokyo",
    )
    assert tenant.timezone == "Asia/Tokyo"

    t_dict = tenant.to_dict()
    assert t_dict["timezone"] == "Asia/Tokyo"

    restored = Tenant.from_dict(t_dict)
    assert restored.timezone == "Asia/Tokyo"


def test_multilang_content_analysis_comprehensive():
    # Japanese BEC Wire Transfer
    ja_text = "至急の支払いと振込先変更をお願い申し上げます。社外秘で処理してください。"
    lang_ja = detect_language(ja_text)
    assert lang_ja == "ja"
    matches_ja, score_ja = scan_multilang_keywords(ja_text)
    assert len(matches_ja) >= 2
    assert score_ja >= 40

    # Spanish Financial Urgency
    es_text = "Aviso de pago urgente por factura vencida antes del corte."
    lang_es = detect_language(es_text)
    assert lang_es == "es"
    matches_es, score_es = scan_multilang_keywords(es_text)
    assert len(matches_es) >= 2
    assert score_es >= 30

    # French Credential Phishing
    fr_text = "Action requise immédiatement: confirmer votre compte car mot de passe expiré."
    lang_fr = detect_language(fr_text)
    assert lang_fr == "fr"
    matches_fr, score_fr = scan_multilang_keywords(fr_text)
    assert len(matches_fr) >= 2
    assert score_fr >= 30
