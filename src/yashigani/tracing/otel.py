"""
OpenTelemetry tracing setup — Phase 9.

Initialises the OTLP gRPC exporter pointing at the otel-collector.
W3C traceparent propagated inbound and outbound.
X-Trace-Id response header set from the active span's trace ID.

env:
  OTEL_EXPORTER_OTLP_ENDPOINT — default: http://otel-collector:4317
  YASHIGANI_ENV               — sets deployment.environment resource attribute
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import yashigani

logger = logging.getLogger(__name__)

_tracer = None
_tracer_provider = None


def setup_tracer(service_name: str = "yashigani-gateway") -> None:
    """Call once at application startup."""
    global _tracer, _tracer_provider
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.propagate import set_global_textmap
        from opentelemetry.propagators.composite import CompositePropagator

        try:
            from opentelemetry.propagators.tracecontext import TraceContextTextMapPropagator
        except ImportError:
            from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

        otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
        resource = Resource.create({
            "service.name": service_name,
            "service.version": yashigani.__version__,
            "deployment.environment": os.getenv("YASHIGANI_ENV", "production"),
        })
        provider = TracerProvider(resource=resource)
        otel_insecure = os.getenv("OTEL_EXPORTER_INSECURE", "false").lower() in ("true", "1", "yes")
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=otel_insecure)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        set_global_textmap(CompositePropagator([TraceContextTextMapPropagator()]))
        _tracer_provider = provider
        _tracer = trace.get_tracer(service_name)
        logger.info("OpenTelemetry tracer configured: endpoint=%s", otlp_endpoint)
    except ImportError as exc:
        logger.warning("OpenTelemetry packages not installed — tracing disabled: %s", exc)
    except Exception as exc:
        logger.warning("OpenTelemetry setup failed — tracing disabled: %s", exc)


def get_tracer():
    """Return the active tracer, or a no-op tracer if OTEL is unavailable."""
    global _tracer
    if _tracer is None:
        try:
            from opentelemetry import trace
            _tracer = trace.get_tracer("yashigani")
        except Exception:
            return _NoOpTracer()
    return _tracer


def current_trace_id() -> str:
    """Return current W3C trace ID hex string, or empty string."""
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.trace_id:
            return format(ctx.trace_id, "032x")
    except Exception:
        pass
    return ""


class _NoOpTracer:
    class _NoOpSpan:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def set_attribute(self, *args): pass
        def set_status(self, *args): pass
        def record_exception(self, *args): pass

    def start_as_current_span(self, name, **kwargs):
        return self._NoOpSpan()

    def start_span(self, name, **kwargs):
        return self._NoOpSpan()
