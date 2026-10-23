"""
EACP Telemetry & Observability:
W3C TraceContext distributed tracing propagation and standard Prometheus/OpenMetrics exporter.
Cloud & vendor agnostic.
"""

from __future__ import annotations
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class TraceContext:
    """
    W3C TraceContext (traceparent) representation for distributed multi-agent tracing.
    Format: 00-{trace_id}-{span_id}-{trace_flags}
    """
    trace_id: str
    span_id: str
    trace_flags: str = "01"

    @classmethod
    def new_root(cls) -> TraceContext:
        """Generates a new root trace context."""
        trace_id = secrets.token_hex(16)  # 32 hex chars (128-bit)
        span_id = secrets.token_hex(8)    # 16 hex chars (64-bit)
        return cls(trace_id=trace_id, span_id=span_id, trace_flags="01")

    def create_child(self) -> TraceContext:
        """Creates a child span context preserving the trace_id."""
        return TraceContext(
            trace_id=self.trace_id,
            span_id=secrets.token_hex(8),
            trace_flags=self.trace_flags,
        )

    def to_header(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{self.trace_flags}"

    @classmethod
    def parse(cls, header: str) -> Optional[TraceContext]:
        parts = header.strip().split("-")
        if len(parts) == 4 and parts[0] == "00" and len(parts[1]) == 32 and len(parts[2]) == 16:
            return cls(trace_id=parts[1], span_id=parts[2], trace_flags=parts[3])
        return None


class PrometheusMetric:
    """Represents a Prometheus/OpenMetrics timeseries."""

    def __init__(self, name: str, help_text: str, metric_type: str):
        self.name = name
        self.help_text = help_text
        self.metric_type = metric_type
        self.samples: Dict[Tuple[Tuple[str, str], ...], float] = {}

    def set(self, value: float, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        self.samples[key] = float(value)

    def inc(self, value: float = 1.0, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        self.samples[key] = self.samples.get(key, 0.0) + float(value)


class EacpMetrics:
    """
    Prometheus / OpenMetrics registry for EACP microkernel mesh.
    Provides standard metrics with zero third-party dependencies.
    """

    def __init__(self):
        self.frames_total = PrometheusMetric(
            "eacp_frames_total",
            "Total count of routed EACP protocol frames",
            "counter",
        )
        self.active_rendezvous = PrometheusMetric(
            "eacp_active_rendezvous_total",
            "Current count of active QNX rendezvous pairs in flight",
            "gauge",
        )
        self.registered_agents = PrometheusMetric(
            "eacp_registered_agents_total",
            "Current count of registered Agent-PINs",
            "gauge",
        )
        self.platsec_denials = PrometheusMetric(
            "eacp_platsec_denials_total",
            "Total PlatSec capability rejections",
            "counter",
        )
        self.deadlocks_prevented = PrometheusMetric(
            "eacp_deadlocks_prevented_total",
            "Total circular rendezvous deadlocks detected and prevented",
            "counter",
        )
        self.bytes_transmitted = PrometheusMetric(
            "eacp_bytes_transmitted_total",
            "Total bytes transmitted across transport",
            "counter",
        )

    def export_prometheus_text(self) -> str:
        """Formats all metrics into Prometheus standard plain text format."""
        lines: List[str] = []
        metrics = [
            self.frames_total,
            self.active_rendezvous,
            self.registered_agents,
            self.platsec_denials,
            self.deadlocks_prevented,
            self.bytes_transmitted,
        ]
        for m in metrics:
            lines.append(f"# HELP {m.name} {m.help_text}")
            lines.append(f"# TYPE {m.name} {m.metric_type}")
            if not m.samples:
                lines.append(f"{m.name} 0")
            else:
                for labels, val in m.samples.items():
                    if labels:
                        lbl_str = "{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}"
                    else:
                        lbl_str = ""
                    lines.append(f"{m.name}{lbl_str} {val}")
        return "\n".join(lines) + "\n"
