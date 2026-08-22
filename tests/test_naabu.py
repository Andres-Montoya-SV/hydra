"""Tests for the naabu confirmation pass (cross-run port-noise mitigation).

Background: manual, repeated `naabu` invocations against a real
shared-hosting target (www.metaversejustice.com, DreamHost) with identical
arguments returned a completely different set of "open" ports on every
single run (e.g. {3986, 5432, 1433, 548, 6000} vs {993, 6001, 37, 990,
1027}, zero overlap) — proving the noise originates in naabu/the network
path itself (most likely a shared-hosting/anti-scan middlebox completing
TCP handshakes for an essentially random sample of ports per scan), not in
Hydra's parsing code. `NaabuPlugin` mitigates this by re-probing exactly
the first pass's open ports a second time and keeping only the
intersection.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import PipelineContext
from modules.naabu import NaabuPlugin

_SCOPE = CollectionScope.from_seeds(
    ["www.metaversejustice.com", "metaversejustice.com", "example.com"],
    patterns=["metaversejustice.com", "example.com"],
)


def _ctx(output_dir):
    return PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)


@pytest.mark.asyncio
async def test_confirm_ports_keeps_only_ports_that_reproduce(
    settings: Settings, tmp_path: Path
) -> None:
    """If a second, targeted naabu pass does not see a port that the first
    pass reported open, that port must be dropped — it never reproduced,
    so it is noise, not a real finding."""
    plugin = NaabuPlugin(settings)
    context = _ctx(tmp_path)
    input_path = tmp_path / "resolved.txt"
    input_path.write_text("www.metaversejustice.com\n", encoding="utf-8")

    first_pass_lines = [
        "www.metaversejustice.com:646",
        "www.metaversejustice.com:5432",
        "www.metaversejustice.com:5190",
    ]
    # Confirmation pass only reproduces port 5190 — the other two were
    # single-run noise, exactly like the real-world evidence.
    confirmation_stdout = "www.metaversejustice.com:5190\n"

    async def fake_run_command(args, **kwargs):
        assert "-p" in args
        return 0, confirmation_stdout, ""

    with patch("modules.naabu.asyncio.sleep", new=AsyncMock()):
        with patch("modules.naabu.run_command", new=fake_run_command):
            confirmed = await plugin._confirm_ports(context, input_path, first_pass_lines)

    assert confirmed == ["www.metaversejustice.com:5190"]


@pytest.mark.asyncio
async def test_confirm_ports_keeps_all_when_fully_reproduced(
    settings: Settings, tmp_path: Path
) -> None:
    """A genuinely stable service (e.g. a real web server) must not be
    dropped just because confirmation is enabled."""
    plugin = NaabuPlugin(settings)
    context = _ctx(tmp_path)
    input_path = tmp_path / "resolved.txt"
    input_path.write_text("example.com\n", encoding="utf-8")

    first_pass_lines = ["example.com:80", "example.com:443"]

    async def fake_run_command(args, **kwargs):
        return 0, "example.com:80\nexample.com:443\n", ""

    with patch("modules.naabu.asyncio.sleep", new=AsyncMock()):
        with patch("modules.naabu.run_command", new=fake_run_command):
            confirmed = await plugin._confirm_ports(context, input_path, first_pass_lines)

    assert sorted(confirmed) == sorted(first_pass_lines)


@pytest.mark.asyncio
async def test_confirm_ports_falls_back_to_first_pass_on_error(
    settings: Settings, tmp_path: Path
) -> None:
    """If the confirmation pass itself fails to execute (e.g. binary
    missing, timeout), fail open to the first pass rather than silently
    discarding all results."""
    plugin = NaabuPlugin(settings)
    context = _ctx(tmp_path)
    input_path = tmp_path / "resolved.txt"
    input_path.write_text("example.com\n", encoding="utf-8")

    first_pass_lines = ["example.com:80"]

    async def failing_run_command(args, **kwargs):
        raise RuntimeError("naabu binary not found")

    with patch("modules.naabu.asyncio.sleep", new=AsyncMock()):
        with patch("modules.naabu.run_command", new=failing_run_command):
            confirmed = await plugin._confirm_ports(context, input_path, first_pass_lines)

    assert confirmed == first_pass_lines


@pytest.mark.asyncio
async def test_naabu_plugin_run_drops_unconfirmed_ports_and_warns(
    settings: Settings, tmp_path: Path
) -> None:
    """End-to-end: NaabuPlugin.run() must write only confirmed ports to
    naabu.txt and record a warning explaining why ports were dropped, so
    the noise-filtering is visible/auditable, not silent."""
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = _ctx(output_dir)
    input_path = output_dir / "resolved.txt"
    input_path.write_text("www.metaversejustice.com\n", encoding="utf-8")

    plugin = NaabuPlugin(settings)

    async def fake_execute(ctx, args, out_path, **kwargs):
        from core.plugin_base import PluginResult

        out_path.write_text(
            "www.metaversejustice.com:646\n"
            "www.metaversejustice.com:5432\n"
            "www.metaversejustice.com:5190\n",
            encoding="utf-8",
        )
        return PluginResult(success=True, output_path=out_path, lines_produced=3)

    async def fake_run_command(args, **kwargs):
        return 0, "www.metaversejustice.com:5190\n", ""

    with patch.object(plugin, "_execute", new=fake_execute):
        with patch("modules.naabu.asyncio.sleep", new=AsyncMock()):
            with patch("modules.naabu.run_command", new=fake_run_command):
                result = await plugin.run(context, input_path)

    assert result.lines_produced == 1
    from utils.files import read_lines

    final_ports = read_lines(output_dir / "naabu.txt")
    assert final_ports == ["www.metaversejustice.com:5190"]
    assert any("confirmation pass" in w for w in context.warnings)


# Real nmap -sV stdout captured from the user's manual confirmation against
# www.metaversejustice.com (DreamHost shared hosting) — all four impossible
# canary ports reported open. This is the ground-truth fixture the previous
# naabu-based canary failed to reproduce.
_METAVERSE_TARPIT_NMAP_STDOUT = """\
Starting Nmap 7.97 ( https://nmap.org )
Nmap scan report for www.metaversejustice.com (173.236.247.198)
Host is up.
rDNS record for 173.236.247.198: apache2-grog.iad1-shared-b8-22.dreamhost.com

PORT      STATE SERVICE VERSION
6/tcp     open  unknown
9999/tcp  open  abyss?
23456/tcp open  aequus?
54321/tcp open  unknown

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 165.00 seconds
"""

_NORMAL_HOST_NMAP_STDOUT = """\
Starting Nmap 7.97 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up.

PORT      STATE    SERVICE VERSION
6/tcp     filtered unknown
21111/tcp filtered unknown
33222/tcp closed   unknown
44333/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 3.00 seconds
"""


def test_tarpit_nmap_argv_includes_patient_timing_flags() -> None:
    """Lock the slow-tarpit timing flags so they cannot regress silently.

    Network latency of a real tarpit cannot be simulated in CI; instead we
    assert the patient argv always carries ``-T1 --max-retries 10
    --host-timeout 5m`` (run 20260806_183325 false-negative root cause;
    ``-T2`` was empirically still too fast against this host).
    """
    fast = NaabuPlugin._build_tarpit_nmap_argv(
        "/usr/bin/nmap", [6, 9999, 23456, 54321], "www.metaversejustice.com", patient=False
    )
    patient = NaabuPlugin._build_tarpit_nmap_argv(
        "/usr/bin/nmap", [6, 9999, 23456, 54321], "www.metaversejustice.com", patient=True
    )

    assert fast[:4] == ["/usr/bin/nmap", "-sV", "-Pn", "--version-light"]
    assert "-p" in fast and "6,9999,23456,54321" in fast
    assert fast[-1] == "www.metaversejustice.com"
    assert "-T1" not in fast
    assert "--host-timeout" not in fast

    assert patient[:4] == ["/usr/bin/nmap", "-sV", "-Pn", "--version-light"]
    assert "-T1" in patient
    assert patient[patient.index("--max-retries") + 1] == "10"
    assert patient[patient.index("--host-timeout") + 1] == "5m"
    assert patient[-1] == "www.metaversejustice.com"


@pytest.mark.asyncio
async def test_run_tarpit_check_retries_with_patient_timing_after_filtered_fast_pass(
    settings: Settings, tmp_path: Path
) -> None:
    """Fast pass filtered → patient pass must run and can flip to tarpit."""
    plugin = NaabuPlugin(settings)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = _ctx(output_dir)
    input_path = output_dir / "resolved.txt"
    input_path.write_text("www.metaversejustice.com\n", encoding="utf-8")
    canaries = [6, 9999, 23456, 54321]
    calls: list[list[str]] = []

    async def fake_run_command(args, **kwargs):
        calls.append(list(args))
        if "-T1" in args:
            return 0, _METAVERSE_TARPIT_NMAP_STDOUT, ""
        return 0, _NORMAL_HOST_NMAP_STDOUT, ""

    with patch.object(plugin, "_select_canary_ports", return_value=canaries):
        with patch.object(plugin, "_nmap_binary", return_value=Path("/usr/bin/nmap")):
            with patch("modules.naabu.run_command", new=fake_run_command):
                tarpit_hosts = await plugin._run_tarpit_check(
                    context, input_path, ["www.metaversejustice.com"]
                )

    assert len(calls) == 2
    assert "-T1" not in calls[0]
    assert "-T1" in calls[1]
    assert "--max-retries" in calls[1] and "10" in calls[1]
    assert "--host-timeout" in calls[1] and "5m" in calls[1]
    assert tarpit_hosts == {"www.metaversejustice.com"}

    from utils.files import read_jsonl

    record = read_jsonl(output_dir / "tarpit_check.jsonl")[0]
    assert record["tarpit_suspected"] is True
    assert record["probe_pass"] == "patient"
    assert "-T1" in record["probe_technique"]
    raw = (output_dir / record["raw_artifact"]).read_text(encoding="utf-8")
    # Both passes must be auditable in the raw artifact.
    assert raw.count("$ ") >= 2
    assert "--host-timeout 5m" in raw


@pytest.mark.asyncio
async def test_run_tarpit_check_uses_nmap_sv_and_flags_metaverse_style_tarpit(
    settings: Settings, tmp_path: Path
) -> None:
    """Fixture: the exact nmap -sV evidence the user confirmed twice.

    Canaries must be probed with ``nmap -sV`` (not naabu), detect
    tarpit_suspected:true at threshold, and persist a raw_artifact containing
    the exact command + full nmap stdout for audit.
    """
    plugin = NaabuPlugin(settings)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = _ctx(output_dir)
    input_path = output_dir / "resolved.txt"
    input_path.write_text("www.metaversejustice.com\n", encoding="utf-8")
    canaries = [6, 9999, 23456, 54321]

    async def fake_run_command(args, **kwargs):
        # Must be nmap -sV, not naabu.
        assert args[0].endswith("nmap") or "nmap" in args[0]
        assert "-sV" in args
        assert "-Pn" in args
        assert "-p" in args
        assert "naabu" not in args[0]
        return 0, _METAVERSE_TARPIT_NMAP_STDOUT, ""

    with patch.object(plugin, "_select_canary_ports", return_value=canaries):
        with patch.object(plugin, "_nmap_binary", return_value=Path("/usr/bin/nmap")):
            with patch("modules.naabu.run_command", new=fake_run_command):
                tarpit_hosts = await plugin._run_tarpit_check(
                    context, input_path, ["www.metaversejustice.com"]
                )

    assert tarpit_hosts == {"www.metaversejustice.com"}
    assert any("tarpit" in w.lower() for w in context.warnings)

    from utils.files import read_jsonl

    records = read_jsonl(output_dir / "tarpit_check.jsonl")
    assert len(records) == 1
    assert records[0]["tarpit_suspected"] is True
    assert records[0]["probe_technique"] == "nmap -sV -Pn"
    assert records[0]["probe_error"] is None
    assert sorted(records[0]["canary_open_ports"]) == [6, 9999, 23456, 54321]
    assert records[0]["raw_artifact"]
    assert not Path(str(records[0]["raw_artifact"])).is_absolute()
    raw = output_dir / records[0]["raw_artifact"]
    assert raw.exists()
    raw_text = raw.read_text(encoding="utf-8")
    assert "$ " in raw_text and "-sV" in raw_text
    assert "6/tcp     open" in raw_text
    assert "----- stdout -----" in raw_text


@pytest.mark.asyncio
async def test_run_tarpit_check_does_not_flag_host_with_filtered_canaries(
    settings: Settings, tmp_path: Path
) -> None:
    """Normal host: nmap -sV reports filtered/closed on all canaries."""
    plugin = NaabuPlugin(settings)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = _ctx(output_dir)
    input_path = output_dir / "resolved.txt"
    input_path.write_text("example.com\n", encoding="utf-8")

    async def fake_run_command(args, **kwargs):
        return 0, _NORMAL_HOST_NMAP_STDOUT, ""

    with patch.object(plugin, "_select_canary_ports", return_value=[6, 21111, 33222, 44333]):
        with patch.object(plugin, "_nmap_binary", return_value=Path("/usr/bin/nmap")):
            with patch("modules.naabu.run_command", new=fake_run_command):
                tarpit_hosts = await plugin._run_tarpit_check(context, input_path, ["example.com"])

    assert tarpit_hosts == set()
    from utils.files import read_jsonl

    record = read_jsonl(output_dir / "tarpit_check.jsonl")[0]
    assert record["tarpit_suspected"] is False
    assert record["canary_open_ports"] == []
    assert record["probe_error"] is None
    assert record["raw_artifact"]


@pytest.mark.asyncio
async def test_run_tarpit_check_does_not_silently_treat_probe_failure_as_clean(
    settings: Settings, tmp_path: Path
) -> None:
    """Regression for run 20260806_180339: when the canary tool fatally fails
    (naabu historically printed 'no valid ipv4 or ipv6 targets were found'
    on stderr with empty stdout), we must NOT emit a clean
    tarpit_suspected:false — that was the false-negative. Record probe_error
    and leave the host unscored for tarpit instead.
    """
    plugin = NaabuPlugin(settings)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = _ctx(output_dir)
    input_path = output_dir / "resolved.txt"
    input_path.write_text("www.metaversejustice.com\n", encoding="utf-8")

    async def failing_run_command(args, **kwargs):
        return (
            1,
            "",
            "[FTL] Could not run enumeration: no valid ipv4 or ipv6 targets were found",
        )

    with patch.object(plugin, "_select_canary_ports", return_value=[6, 9999, 23456, 54321]):
        with patch.object(plugin, "_nmap_binary", return_value=Path("/usr/bin/nmap")):
            with patch("modules.naabu.run_command", new=failing_run_command):
                tarpit_hosts = await plugin._run_tarpit_check(
                    context, input_path, ["www.metaversejustice.com"]
                )

    assert tarpit_hosts == set()
    assert any("inconclusive" in w.lower() or "probe failed" in w.lower() for w in context.warnings)

    from utils.files import read_jsonl

    record = read_jsonl(output_dir / "tarpit_check.jsonl")[0]
    assert record["probe_error"]
    assert "no valid ipv4" in record["probe_error"] or "no port table" in record["probe_error"]
    assert record["raw_artifact"]
    # Must NOT look like a confident negative
    assert record.get("canary_open_ports") == []


@pytest.mark.asyncio
async def test_run_tarpit_check_records_exception_as_probe_error_not_clean(
    settings: Settings, tmp_path: Path
) -> None:
    plugin = NaabuPlugin(settings)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = _ctx(output_dir)
    input_path = output_dir / "resolved.txt"
    input_path.write_text("example.com\n", encoding="utf-8")

    async def failing_run_command(args, **kwargs):
        raise RuntimeError("nmap binary not found")

    with patch.object(plugin, "_nmap_binary", return_value=Path("/usr/bin/nmap")):
        with patch("modules.naabu.run_command", new=failing_run_command):
            tarpit_hosts = await plugin._run_tarpit_check(context, input_path, ["example.com"])

    assert tarpit_hosts == set()
    from utils.files import read_jsonl

    record = read_jsonl(output_dir / "tarpit_check.jsonl")[0]
    assert "nmap binary not found" in record["probe_error"]
    assert record["raw_artifact"]


@pytest.mark.asyncio
async def test_naabu_run_skips_real_scan_when_all_hosts_tarpit_suspected(
    settings: Settings, tmp_path: Path
) -> None:
    """If every candidate host fails the canary check, the real naabu scan
    must be skipped entirely — not run and then discarded — to avoid
    burning time producing a port list already known to be fabricated."""
    plugin = NaabuPlugin(settings)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = _ctx(output_dir)
    input_path = output_dir / "resolved.txt"
    input_path.write_text("www.metaversejustice.com\n", encoding="utf-8")

    async def fake_canary_response(args, **kwargs):
        return 0, _METAVERSE_TARPIT_NMAP_STDOUT, ""

    async def must_not_run(*args, **kwargs):
        raise AssertionError("real naabu scan must not run for an all-tarpit target set")

    with patch.object(plugin, "_select_canary_ports", return_value=[6, 9999, 23456, 54321]):
        with patch.object(plugin, "_nmap_binary", return_value=Path("/usr/bin/nmap")):
            with patch("modules.naabu.run_command", new=fake_canary_response):
                with patch.object(plugin, "_execute", new=must_not_run):
                    result = await plugin.run(context, input_path)

    assert result.success is True
    assert result.lines_produced == 0
    assert "tarpit" in result.message.lower()
    assert context.metadata["tarpit_suspected_hosts"] == ["www.metaversejustice.com"]


@pytest.mark.asyncio
async def test_naabu_run_scans_only_non_tarpit_hosts_when_mixed(
    settings: Settings, tmp_path: Path
) -> None:
    """With one normal host and one tarpit-suspected host in the same run,
    the real scan must proceed for the normal host and exclude only the
    suspected one — detecting tarpit behavior must not blind the whole run."""
    plugin = NaabuPlugin(settings)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = _ctx(output_dir)
    input_path = output_dir / "resolved.txt"
    input_path.write_text("www.metaversejustice.com\nexample.com\n", encoding="utf-8")

    async def fake_canary_response(args, **kwargs):
        host = args[-1]
        if host == "www.metaversejustice.com":
            return 0, _METAVERSE_TARPIT_NMAP_STDOUT, ""
        return 0, _NORMAL_HOST_NMAP_STDOUT, ""

    scanned_target_files: list[str] = []

    async def fake_execute(ctx, args, out_path, **kwargs):
        from core.plugin_base import PluginResult

        scanned_target_files.append(Path(args[args.index("-l") + 1]).read_text(encoding="utf-8"))
        out_path.write_text("example.com:443\n", encoding="utf-8")
        return PluginResult(success=True, output_path=out_path, lines_produced=1)

    with patch.object(plugin, "_select_canary_ports", return_value=[6, 9999, 23456, 54321]):
        with patch.object(plugin, "_nmap_binary", return_value=Path("/usr/bin/nmap")):
            with patch("modules.naabu.run_command", new=fake_canary_response):
                with patch.object(plugin, "_execute", new=fake_execute):
                    with patch.object(settings, "naabu_confirm_open_ports", False):
                        result = await plugin.run(context, input_path)

    assert "www.metaversejustice.com" not in scanned_target_files[0]
    assert "example.com" in scanned_target_files[0]
    assert result.lines_produced == 1
    assert context.metadata["tarpit_suspected_hosts"] == ["www.metaversejustice.com"]
    assert "1 host(s) excluded" in result.message


@pytest.mark.asyncio
async def test_naabu_confirmation_disabled_keeps_raw_first_pass(
    settings: Settings, tmp_path: Path
) -> None:
    """With NAABU_CONFIRM_OPEN_PORTS disabled, behavior must be unchanged
    from before this feature existed (no confirmation pass triggered)."""
    settings.naabu_confirm_open_ports = False
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = _ctx(output_dir)
    input_path = output_dir / "resolved.txt"
    input_path.write_text("example.com\n", encoding="utf-8")

    plugin = NaabuPlugin(settings)

    async def fake_execute(ctx, args, out_path, **kwargs):
        from core.plugin_base import PluginResult

        out_path.write_text("example.com:80\nexample.com:9999\n", encoding="utf-8")
        return PluginResult(success=True, output_path=out_path, lines_produced=2)

    with patch.object(plugin, "_execute", new=fake_execute):
        with patch(
            "modules.naabu.run_command",
            new=AsyncMock(side_effect=AssertionError("must not be called")),
        ):
            result = await plugin.run(context, input_path)

    assert result.lines_produced == 2
