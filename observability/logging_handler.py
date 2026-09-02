"""
Centralized Redacting JSON Logging Handler.
Formats application logs as structured JSON and applies automated PII/secret redaction at the handler boundary.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict


class RedactingJsonFormatter(logging.Formatter):
    # PII & Secret Redaction Patterns
    EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    BEARER_REGEX = re.compile(r"(Bearer\s+)[A-Za-z0-9._~\-+=/]+", re.IGNORECASE)
    SECRET_KEY_REGEX = re.compile(r'(["\']?(?:secret|password|api_key|token)["\']?\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)', re.IGNORECASE)

    @classmethod
    def redact_text(cls, text: str) -> str:
        """Redact sensitive PII and secrets from string."""
        if not text:
            return text
        redacted = cls.EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)
        redacted = cls.BEARER_REGEX.sub(r"\1[REDACTED_TOKEN]", redacted)
        redacted = cls.SECRET_KEY_REGEX.sub(r"\1[REDACTED_SECRET]\3", redacted)
        return redacted

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        redacted_msg = self.redact_text(message)

        log_data: Dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": redacted_msg,
            "filename": record.filename,
            "lineno": record.lineno,
        }

        if hasattr(record, "trace_id"):
            log_data["trace_id"] = getattr(record, "trace_id")
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class RedactingJsonLogHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__()
        self.setFormatter(RedactingJsonFormatter())
