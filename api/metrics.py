"""Productization Phase 11d: Prometheus metrics (`GET /metrics`, operators only).

Requests (counted by a middleware, per process):

- `hydra_http_requests_total{method, route, status}`
- `hydra_http_request_duration_seconds{method, route}` (histogram)

`route` is the matched route template (`/organizations/{organization_id}/assets`),
never the raw path. Ids never become label values, and unmatched paths
share one `unmatched` label, so a scanner probing random URLs can't blow
up the series count.

State (read at scrape time):

- `hydra_control_db_up`: whether the control database answered.
- `hydra_scans{status}`: the scan queue and history.
- `hydra_integration_deliveries{status}`: the outbox, including `dead`.
- `hydra_pending_tenant_deletions{kind}`.
- `hydra_loop_seconds_since_alive{loop}`: each background loop's heartbeat.
- `hydra_db_pool{stat}`: the Postgres pool's counters (size, available,
  requests waiting...).

Only aggregates are exposed: no tenant ids, domains or emails.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

from fastapi import FastAPI
from prometheus_client import CollectorRegistry, Counter, Histogram
from prometheus_client.core import GaugeMetricFamily, Metric
from prometheus_client.registry import Collector

from api.db import PostgresBackend
from api.edge import ASGIApp, Message, Receive, Scope, Send

_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


class Metrics:
    """One registry per application (tests create many apps per process)."""

    def __init__(self, app: FastAPI) -> None:
        self.registry = CollectorRegistry()
        self.requests = Counter(
            "hydra_http_requests",
            "HTTP requests handled.",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.duration = Histogram(
            "hydra_http_request_duration_seconds",
            "HTTP request handling time.",
            ["method", "route"],
            buckets=_DURATION_BUCKETS,
            registry=self.registry,
        )
        self.registry.register(_StateCollector(app))


def _gauge(name: str, documentation: str, label: str, values: dict[str, Any]) -> Metric:
    family = GaugeMetricFamily(name, documentation, labels=[label])
    for key, value in sorted(values.items()):
        family.add_metric([str(key)], float(value))
    return family


class _StateCollector(Collector):
    def __init__(self, app: FastAPI) -> None:
        self.app = app

    def collect(self) -> Iterator[Metric]:
        state = self.app.state
        control_db = getattr(state, "control_db", None)
        heartbeats = getattr(state, "loop_heartbeats", None)
        if heartbeats is not None:
            ages = {name: time.monotonic() - last for name, last in heartbeats.timestamps.items()}
            yield _gauge(
                "hydra_loop_seconds_since_alive",
                "Seconds since each background loop last reported in.",
                "loop",
                ages,
            )
        if control_db is None:
            return
        up = GaugeMetricFamily("hydra_control_db_up", "The control database answered.")
        try:
            scans = control_db.scan_status_counts()
            deliveries = control_db.delivery_status_counts()
            deletions = control_db.pending_deletion_counts()
        except Exception:  # an unreachable database is reported, not raised
            up.add_metric([], 0.0)
            yield up
            return
        up.add_metric([], 1.0)
        yield up
        yield _gauge("hydra_scans", "Scans by status.", "status", scans)
        yield _gauge(
            "hydra_integration_deliveries",
            "Integration deliveries by status.",
            "status",
            deliveries,
        )
        yield _gauge(
            "hydra_pending_tenant_deletions", "Scheduled tenant deletions.", "kind", deletions
        )
        if isinstance(control_db.backend, PostgresBackend):
            yield _gauge(
                "hydra_db_pool",
                "Control database connection pool.",
                "stat",
                control_db.backend.pool_stats(),
            )


class MetricsMiddleware:
    def __init__(self, app: ASGIApp, *, metrics: Metrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        status = 500
        started = time.perf_counter()

        async def observing_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, observing_send)
        finally:
            route = getattr(scope.get("route"), "path", None) or "unmatched"
            method = str(scope.get("method", ""))
            self.metrics.requests.labels(method, route, str(status)).inc()
            self.metrics.duration.labels(method, route).observe(time.perf_counter() - started)


def install_metrics(app: FastAPI) -> None:
    """Registered before the edge middleware, so it sits inside it."""
    metrics = Metrics(app)
    app.state.metrics = metrics
    app.add_middleware(MetricsMiddleware, metrics=metrics)
