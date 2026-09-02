"""
Grafana Dashboard Generator.
Exports standard JSON dashboard definitions for monitoring Email Auth Gateway metrics in Grafana.
"""
from __future__ import annotations

import json
from typing import Any, Dict


class GrafanaDashboardGenerator:
    @staticmethod
    def generate_dashboard_json() -> Dict[str, Any]:
        """Generate Grafana dashboard JSON schema."""
        return {
            "dashboard": {
                "id": None,
                "title": "Email Auth Gateway — Operational Overview",
                "tags": ["email-gateway", "security", "prometheus"],
                "timezone": "browser",
                "schemaVersion": 36,
                "version": 1,
                "panels": [
                    {
                        "id": 1,
                        "title": "Inbound Message Throughput (msgs/sec)",
                        "type": "timeseries",
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
                        "targets": [
                            {
                                "expr": 'rate(gateway_messages_processed_total[5m])',
                                "legendFormat": "{{action}}",
                            }
                        ],
                    },
                    {
                        "id": 2,
                        "title": "Pipeline Processing Latency (p99 / p50)",
                        "type": "timeseries",
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
                        "targets": [
                            {
                                "expr": 'rate(gateway_stage_latency_seconds_sum[5m]) / rate(gateway_stage_latency_seconds_count[5m])',
                                "legendFormat": "{{stage}} avg latency",
                            }
                        ],
                    },
                    {
                        "id": 3,
                        "title": "External Provider API Errors",
                        "type": "bargauge",
                        "gridPos": {"h": 6, "w": 12, "x": 0, "y": 8},
                        "targets": [
                            {
                                "expr": 'sum(gateway_external_api_errors_total) by (provider)',
                                "legendFormat": "{{provider}}",
                            }
                        ],
                    },
                    {
                        "id": 4,
                        "title": "Circuit Breaker States",
                        "type": "stat",
                        "gridPos": {"h": 6, "w": 12, "x": 12, "y": 8},
                        "targets": [
                            {
                                "expr": 'gateway_circuit_breaker_state',
                                "legendFormat": "{{breaker}} ({{state}})",
                            }
                        ],
                    },
                ],
            }
        }
