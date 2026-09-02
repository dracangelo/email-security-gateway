"""
Network Segmentation module providing isolated FastAPI application factories:
- create_inbound_app(): Exposes public inbound webhooks and public services. Admin routes are NOT included.
- create_admin_app(): Exposes administrative endpoints, quarantine management, and analytics. Public webhook routes are NOT included.
"""
from __future__ import annotations

from typing import Tuple
from fastapi import FastAPI

from webhook_receiver.app import (
    _lifespan,
    admin_zap_endpoint,
    aws_ses_inbound,
    create_tenant,
    get_quarantine_item,
    get_tenant,
    google_pubsub_inbound,
    healthz,
    list_quarantine,
    list_tenants,
    m365_graph_inbound,
    mailgun_inbound,
    postmark_inbound,
    readyz,
    reject_quarantine_item,
    release_quarantine_item,
    report_phish_endpoint,
    send_quarantine_digest,
    sendgrid_inbound,
    time_of_click_redirect,
    update_tenant,
)


def create_inbound_app() -> FastAPI:
    """Create FastAPI app isolated for public inbound traffic only."""
    app = FastAPI(title="email-auth-gateway-inbound", lifespan=_lifespan)

    # Core public endpoints
    app.add_api_route("/healthz", healthz, methods=["GET"])
    app.add_api_route("/readyz", readyz, methods=["GET"])

    # Inbound webhooks
    app.add_api_route("/webhooks/sendgrid/inbound/{secret}", sendgrid_inbound, methods=["POST"])
    app.add_api_route("/webhooks/mailgun/inbound", mailgun_inbound, methods=["POST"])
    app.add_api_route("/webhooks/aws/ses", aws_ses_inbound, methods=["POST"])
    app.add_api_route("/webhooks/postmark/inbound", postmark_inbound, methods=["POST"])
    app.add_api_route("/webhooks/m365/graph", m365_graph_inbound, methods=["POST"])
    app.add_api_route("/webhooks/google/pubsub", google_pubsub_inbound, methods=["POST"])

    # Public utility services
    app.add_api_route("/toc/redirect", time_of_click_redirect, methods=["GET"])
    app.add_api_route("/api/v1/report-phish", report_phish_endpoint, methods=["POST"])

    return app


def create_admin_app() -> FastAPI:
    """Create FastAPI app isolated for internal admin network traffic only."""
    app = FastAPI(title="email-auth-gateway-admin", lifespan=_lifespan)

    # Core health
    app.add_api_route("/healthz", healthz, methods=["GET"])
    app.add_api_route("/readyz", readyz, methods=["GET"])

    # Admin quarantine & management
    app.add_api_route("/admin/quarantine", list_quarantine, methods=["GET"])
    app.add_api_route("/admin/quarantine/{quarantine_id}", get_quarantine_item, methods=["GET"])
    app.add_api_route("/admin/quarantine/{quarantine_id}/release", release_quarantine_item, methods=["POST"])
    app.add_api_route("/admin/quarantine/{quarantine_id}/reject", reject_quarantine_item, methods=["POST"])
    app.add_api_route("/admin/zap", admin_zap_endpoint, methods=["POST"])
    app.add_api_route("/admin/digest/send", send_quarantine_digest, methods=["POST"])
    app.add_api_route("/admin/tenants", list_tenants, methods=["GET"])
    app.add_api_route("/admin/tenants", create_tenant, methods=["POST"])
    app.add_api_route("/admin/tenants/{tenant_id}", get_tenant, methods=["GET"])
    app.add_api_route("/admin/tenants/{tenant_id}", update_tenant, methods=["PUT"])

    return app


def create_gateway_apps() -> Tuple[FastAPI, FastAPI]:
    """Returns a tuple of (inbound_app, admin_app)."""
    return create_inbound_app(), create_admin_app()
