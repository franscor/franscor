"""Optional OpenTelemetry tracing. A no-op unless `opentelemetry-api` is installed
and the application configured a tracer provider (FRANSCOR never installs one).

Spans: ``franscor.delegate`` (client) and ``franscor.task`` (server). The W3C
trace context travels in the signed ``task.request`` body as ``trace``, so a
trace started in TypeScript continues in Python and vice versa. Attributes
are metadata only — capability, task id, peer, risk, status — never inputs.
"""

from __future__ import annotations

import contextlib
from typing import Any, Dict, Iterator, Optional

try:  # pragma: no cover - exercised when the extra is installed
    from opentelemetry import propagate, trace
    from opentelemetry.trace import SpanKind, Status, StatusCode

    _tracer = trace.get_tracer("franscor")
except ImportError:  # pragma: no cover
    trace = None

MAX_CARRIER = 512


class _NullSpan:
    def set_attribute(self, *_: Any) -> None:
        pass

    def fail(self, *_: Any) -> None:
        pass


class _Span:
    def __init__(self, span):
        self._span = span

    def set_attribute(self, key: str, value: Any) -> None:
        self._span.set_attribute(key, value)

    def fail(self, description: str) -> None:
        self._span.set_status(Status(StatusCode.ERROR, description))


def enabled() -> bool:
    return trace is not None


@contextlib.contextmanager
def client_span(name: str, attrs: Dict[str, Any]) -> Iterator[tuple]:
    """Yields (span, carrier). Put the carrier in the request body."""
    if trace is None:
        yield _NullSpan(), None
        return
    with _tracer.start_as_current_span(name, kind=SpanKind.CLIENT, attributes=attrs) as span:
        carrier: Dict[str, str] = {}
        propagate.inject(carrier)
        yield _Span(span), carrier or None


@contextlib.contextmanager
def server_span(name: str, attrs: Dict[str, Any], carrier: Optional[Any]) -> Iterator[Any]:
    if trace is None:
        yield _NullSpan()
        return
    parent = None
    if valid_carrier(carrier):
        parent = propagate.extract(carrier)
    with _tracer.start_as_current_span(name, context=parent, kind=SpanKind.SERVER,
                                       attributes=attrs) as span:
        yield _Span(span)


def valid_carrier(carrier: Any) -> bool:
    return (isinstance(carrier, dict) and len(carrier) <= 4
            and all(isinstance(k, str) and isinstance(v, str) for k, v in carrier.items())
            and sum(len(k) + len(v) for k, v in carrier.items()) <= MAX_CARRIER)
