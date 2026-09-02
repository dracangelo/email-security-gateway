"""
Synthetic Canary Probe Runner.
Periodically injects synthetic test messages to verify end-to-end pipeline health and measure baseline latency.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, Optional


class CanaryProbe:
    def __init__(self, process_message_func: Optional[Any] = None):
        self.process_message_func = process_message_func
        self.last_probe_result: Optional[Dict[str, Any]] = None

    async def run_canary_check(self) -> Dict[str, Any]:
        """Execute synthetic canary transaction through process_message pipeline."""
        start_time = time.time()

        canary_payload = {
            "message_id": f"canary_msg_{int(start_time)}",
            "envelope_from": "canary-probe@gateway-health.local",
            "envelope_to": ["synthetic-check@gateway-health.local"],
            "from_header": "Synthetic Canary Probe <canary-probe@gateway-health.local>",
            "text_body": "Gateway Synthetic Health Check Message.",
            "html_body": "<html><body><p>Gateway Synthetic Health Check Message.</p></body></html>",
            "raw_message": b"Subject: Canary Probe\r\n\r\nGateway Synthetic Health Check Message.",
        }

        status = "HEALTHY"
        error_msg = None
        result = None

        if self.process_message_func:
            try:
                result = await self.process_message_func(**canary_payload)
            except Exception as exc:
                status = "UNHEALTHY"
                error_msg = str(exc)
        else:
            # Simulated probe for unit tests
            await asyncio.sleep(0.01)
            result = {"action": "deliver", "canary": True}

        duration_ms = (time.time() - start_time) * 1000.0

        self.last_probe_result = {
            "timestamp": start_time,
            "status": status,
            "latency_ms": round(duration_ms, 2),
            "error": error_msg,
            "result": result,
        }
        return self.last_probe_result
