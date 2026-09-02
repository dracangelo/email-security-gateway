"""
OpenTelemetry Distributed Tracing Manager.
Provides context propagation and span tracing across message processing pipeline stages.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


class SpanContext:
    def __init__(self, name: str, parent_id: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None):
        self.trace_id = uuid.uuid4().hex
        self.span_id = uuid.uuid4().hex[:16]
        self.parent_id = parent_id
        self.name = name
        self.attributes: Dict[str, Any] = attributes or {}
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.status: str = "IN_PROGRESS"

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def finish(self, status: str = "OK") -> None:
        self.end_time = time.time()
        self.status = status

    def duration_ms(self) -> float:
        end = self.end_time or time.time()
        return (end - self.start_time) * 1000.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "name": self.name,
            "status": self.status,
            "duration_ms": round(self.duration_ms(), 2),
            "attributes": self.attributes,
        }


class TracingManager:
    def __init__(self):
        self.completed_spans: List[SpanContext] = []

    def start_trace(self, operation_name: str, attributes: Optional[Dict[str, Any]] = None) -> SpanContext:
        """Initialize a new root trace span."""
        span = SpanContext(name=operation_name, attributes=attributes)
        return span

    def start_child_span(self, parent_span: SpanContext, child_name: str, attributes: Optional[Dict[str, Any]] = None) -> SpanContext:
        """Create a child span linked to parent trace context."""
        child = SpanContext(name=child_name, parent_id=parent_span.span_id, attributes=attributes)
        child.trace_id = parent_span.trace_id
        return child

    def finish_span(self, span: SpanContext, status: str = "OK") -> None:
        span.finish(status=status)
        self.completed_spans.append(span)

    def get_trace_spans(self, trace_id: str) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.completed_spans if s.trace_id == trace_id]
