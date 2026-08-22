"""Field-level historical diff and previous-run selection."""

from __future__ import annotations

from core.assets import Host, HttpService, Port, ScanRun, TechnologyFinding, TlsCertificate
from core.diff import diff_runs
from core.store import AssetStore


def _host(domain: str, **kwargs) -> Host:
    host = Host(domain=domain, dns_resolved=True)
    for key, value in kwargs.items():
        setattr(host, key, value)
    return host


def test_previous_run_uses_target_overlap(tmp_path) -> None:
    store = AssetStore(tmp_path / "db.sqlite")
    store.create_run(
        ScanRun(run_id="unrelated", started_at="2026-01-01T00:00:00Z", targets=["other.com"])
    )
    store.finish_run("unrelated", host_count=1, alive_count=0, warnings=[], errors=[])
    store.create_run(
        ScanRun(run_id="old", started_at="2026-01-02T00:00:00Z", targets=["example.com"])
    )
    store.finish_run("old", host_count=1, alive_count=0, warnings=[], errors=[])
    store.create_run(
        ScanRun(run_id="new", started_at="2026-01-03T00:00:00Z", targets=["example.com"])
    )
    store.create_run(
        ScanRun(run_id="crash", started_at="2026-01-04T00:00:00Z", targets=["example.com"])
    )
    assert store.find_previous_run("new") == "old"
    store.create_run(
        ScanRun(run_id="newer", started_at="2026-01-05T00:00:00Z", targets=["example.com"])
    )
    assert store.find_previous_run("newer") == "old"


def test_field_level_certificate_and_ip_diff(tmp_path) -> None:
    store = AssetStore(tmp_path / "db.sqlite")
    store.create_run(
        ScanRun(run_id="a", started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    old = _host("example.com", ips=["34.75.127.116"], asn="396982")
    old.tls = TlsCertificate(
        host="example.com",
        fingerprint_sha256="a" * 64,
        sans=["example.com"],
        not_after="2026-01-01",
    )
    old.ports.append(Port(host="example.com", port=443, protocol="tcp"))
    old.http_services.append(
        HttpService(
            url="https://example.com",
            host="example.com",
            status_code=200,
            title="Old",
            favicon_hash="111",
            body_hash="bbb",
            technologies=[TechnologyFinding(name="nginx", source="httpx", confidence=90)],
        )
    )
    store.persist_registry("a", {old.domain: old})
    store.finish_run("a", host_count=1, alive_count=1, warnings=[], errors=[])

    store.create_run(
        ScanRun(run_id="b", started_at="2026-01-02T00:00:00Z", targets=["example.com"])
    )
    new = _host("example.com", ips=["35.1.2.3"], asn="1")
    new.tls = TlsCertificate(
        host="example.com",
        fingerprint_sha256="b" * 64,
        sans=["example.com", "virusinspector.top"],
        not_after="2026-06-01",
    )
    new.ports.append(Port(host="example.com", port=80, protocol="tcp"))
    new.http_services.append(
        HttpService(
            url="https://example.com/login",
            host="example.com",
            status_code=401,
            title="New",
            favicon_hash="222",
            body_hash="ccc",
            technologies=[TechnologyFinding(name="apache", source="httpx", confidence=90)],
        )
    )
    www = _host("www.example.com", ips=["35.1.2.3"])
    store.persist_registry("b", {new.domain: new, www.domain: www})
    store.finish_run("b", host_count=2, alive_count=1, warnings=[], errors=[])

    diff = diff_runs(store, "b")
    assert diff is not None
    assert diff.previous_run_id == "a"
    assert diff.new_hosts == ["www.example.com"]
    assert diff.removed_hosts == []
    types = {c.change_type for c in diff.field_changes}
    assert "CERTIFICATE_CHANGED" in types
    assert "SAN_ADDED" in types
    assert "IP_CHANGED" in types
    assert "HTTP_STATUS_CHANGED" in types
    assert "PORTS_CHANGED" in types
    assert "TECHNOLOGIES_CHANGED" in types
    assert "FAVICON_CHANGED" in types
    assert "BODY_HASH_CHANGED" in types
    assert any(
        c.new == ["virusinspector.top"] for c in diff.field_changes if c.change_type == "SAN_ADDED"
    )
    assert diff.new_http == ["https://example.com/login"]
    assert diff.removed_http == ["https://example.com"]
