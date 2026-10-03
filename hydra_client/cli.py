"""`python -m hydra_client`: the Hydra API from a terminal.

Configuration comes from the environment, never from command-line values
other processes could read:
- `HYDRA_API_URL`: the API (default `http://127.0.0.1:8000`);
- `HYDRA_API_KEY`, or `--key-file PATH`: the API key.

A value that starts with `-` goes after `--`, as with any command line:
`python -m hydra_client feedback idea -- "-- a message"`.

Every command prints the API's JSON response. An API error prints its
code, message and request id to stderr; the exit status says what
happened:

| Exit | Meaning |
|---|---|
| 0 | success |
| 1 | the API refused the request (see the error code) |
| 2 | invalid command line |
| 3 | the API could not be reached |
| 4 | `scan-wait`: the scan failed, or the wait timed out |
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO

from hydra_client.client import ApiError, HydraClient, Transport, TransportError

DEFAULT_API_URL = "http://127.0.0.1:8000"
EXIT_API_ERROR, EXIT_UNREACHABLE, EXIT_SCAN_FAILED = 1, 3, 4
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})

Handler = Callable[[argparse.Namespace, HydraClient], Any]


def _path(*parts: str) -> str:
    """Each user-supplied segment is quoted, so it stays one segment."""
    return "/" + "/".join(urllib.parse.quote(part, safe="") for part in parts)


# --- commands: each returns what to print --------------------------------


def _signup(args: argparse.Namespace, client: HydraClient) -> Any:
    created = client.request("POST", "/accounts", body={"email": args.email})
    if args.save_key:
        _save_key(Path(args.save_key), created["api_key"])
        created = {**created, "api_key": f"(saved to {args.save_key})"}
    return created


def _save_key(path: Path, key: str) -> None:
    """Readable by the owner only."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(key + "\n")


def _scan_wait(args: argparse.Namespace, client: HydraClient) -> Any:
    waited = 0.0
    while True:
        scan = client.request("GET", _path("scans", args.scan_id))
        if scan["status"] in ("completed", "failed") or waited >= args.timeout:
            return scan
        client.sleep(args.interval)
        waited += args.interval


def _key_value(item: str) -> tuple[str, str]:
    key, separator, value = item.partition("=")
    if not separator or not key:
        raise argparse.ArgumentTypeError(f"expected key=value, not {item!r}")
    return key, value


def _json_body(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"--data is not valid JSON: {error}") from error


def _call(args: argparse.Namespace, client: HydraClient) -> Any:
    return client.request(args.method, args.path, body=args.data, params=dict(args.param))


_SIMPLE: dict[str, tuple[str, Callable[[argparse.Namespace], tuple[str, str, Any]]]] = {
    "version": ("Release and API contract version.", lambda a: ("GET", "/version", None)),
    "verify-email": (
        "Confirm the account's email with the token from the email.",
        lambda a: ("POST", "/accounts/verify-email", {"token": a.token}),
    ),
    "diagnostics": (
        "The account's state and plain-language hints.",
        lambda a: ("GET", "/account/diagnostics", None),
    ),
    "subscription": ("Tier, limits and usage.", lambda a: ("GET", "/account/subscription", None)),
    "orgs": ("Organizations the account belongs to.", lambda a: ("GET", "/organizations", None)),
    "org-create": (
        "Create an organization.",
        lambda a: ("POST", "/organizations", {"name": a.name}),
    ),
    "demo": (
        "Create (or get) the demo organization with sample data.",
        lambda a: ("POST", "/demo/organization", None),
    ),
    "domain-add": (
        "Start verifying a domain; prints the DNS/file instructions.",
        lambda a: ("POST", "/domains", {"domain": a.domain}),
    ),
    "domain-verify": (
        "Check a domain's verification.",
        lambda a: ("POST", _path("domains", a.domain, "verify"), {"method": a.method}),
    ),
    "scan": (
        "Queue a scan of a verified domain (counts against the quota).",
        lambda a: ("POST", "/scans", {"domain": a.domain, "profile": a.profile}),
    ),
    "scan-status": ("A scan's status.", lambda a: ("GET", _path("scans", a.scan_id), None)),
    "assets": (
        "An organization's assets.",
        lambda a: ("GET", _path("organizations", a.organization_id, "assets"), None),
    ),
    "exposures": (
        "An organization's exposures.",
        lambda a: ("GET", _path("organizations", a.organization_id, "exposures"), None),
    ),
    "exposure-resolve": (
        "Resolve an exposure, with a reason.",
        lambda a: (
            "POST",
            _path("organizations", a.organization_id, "exposures", a.exposure_id, "resolve"),
            {"reason": a.reason},
        ),
    ),
    "monitor": (
        "Turn on monitoring for a verified domain.",
        lambda a: ("POST", _path("domains", a.domain, "monitoring"), {"speed2": a.speed2}),
    ),
    "feedback": (
        "Send feedback to the Hydra team.",
        lambda a: ("POST", "/feedback", {"category": a.category, "message": a.message}),
    ),
}


def _simple(build: Callable[[argparse.Namespace], tuple[str, str, Any]]) -> Handler:
    def run(args: argparse.Namespace, client: HydraClient) -> Any:
        method, path, body = build(args)
        return client.request(method, path, body=body)

    return run


# Each command's arguments: positionals, then options as (flag, keyword arguments).
_ARGUMENTS: dict[str, tuple[list[str], list[tuple[str, dict[str, Any]]]]] = {
    "verify-email": (["token"], []),
    "org-create": (["name"], []),
    "domain-add": (["domain"], []),
    "domain-verify": (
        ["domain"],
        [("--method", {"choices": ["dns_txt", "well_known_file"], "default": "dns_txt"})],
    ),
    "scan": (
        ["domain"],
        [("--profile", {"choices": ["standard", "passive"], "default": "standard"})],
    ),
    "scan-status": (["scan_id"], []),
    "assets": (["organization_id"], []),
    "exposures": (["organization_id"], []),
    "exposure-resolve": (["organization_id", "exposure_id"], [("--reason", {"required": True})]),
    "monitor": (
        ["domain"],
        [("--speed2", {"action": "store_true", "help": "Weekly active scan (Pro+)."})],
    ),
    "feedback": (["category", "message"], []),
}


def _add_arguments(name: str, parser: argparse.ArgumentParser) -> None:
    positionals, options = _ARGUMENTS.get(name, ([], []))
    for argument in positionals:
        parser.add_argument(argument)
    for flag, settings in options:
        parser.add_argument(flag, **settings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hydra-client", description=__doc__.split("\n")[0])
    parser.add_argument("--key-file", help="Read the API key from this file.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, (help_text, build) in _SIMPLE.items():
        sub = commands.add_parser(name, help=help_text)
        _add_arguments(name, sub)
        sub.set_defaults(handler=_simple(build))
    signup = commands.add_parser("signup", help="Create an account; prints the API key ONCE.")
    signup.add_argument("email")
    signup.add_argument("--save-key", help="Write the key to this file (mode 600) instead.")
    signup.set_defaults(handler=_signup)
    wait = commands.add_parser("scan-wait", help="Wait until a scan completes or fails.")
    wait.add_argument("scan_id")
    wait.add_argument("--interval", type=float, default=10.0)
    wait.add_argument("--timeout", type=float, default=3600.0)
    wait.set_defaults(handler=_scan_wait)
    call = commands.add_parser("call", help="Any API request, e.g. call GET /account/export.")
    call.add_argument("method")
    call.add_argument("path")
    call.add_argument("--data", type=_json_body, help="A JSON request body.")
    call.add_argument(
        "--param", type=_key_value, action="append", default=[], help="key=value query parameter."
    )
    call.set_defaults(handler=_call)
    return parser


# --- running ---------------------------------------------------------------


def _api_key(args: argparse.Namespace, env: Mapping[str, str]) -> str | None:
    if args.key_file:
        return Path(args.key_file).read_text().strip()
    return env.get("HYDRA_API_KEY") or None


def _warn_if_cleartext(base_url: str, stderr: TextIO) -> None:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK:
        stderr.write("warning: plain HTTP to a remote host sends the API key unencrypted\n")


def _report(error: ApiError, stderr: TextIO) -> None:
    stderr.write(f"error: {error.code} (HTTP {error.status}): {error.message}\n")
    if error.request_id:
        stderr.write(f"request id: {error.request_id}\n")
    if error.retryable:
        later = f" in {error.retry_after:.0f}s" if error.retry_after else " later"
        stderr.write(f"this can be retried{later}\n")


def _exit_code(command: str, result: Any) -> int:
    if command == "scan-wait" and result.get("status") != "completed":
        return EXIT_SCAN_FAILED
    return 0


def main(
    argv: list[str] | None = None,
    *,
    transport: Transport | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    env: Mapping[str, str] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """`env` defaults to the process environment, read at call time."""
    env = os.environ if env is None else env
    args = build_parser().parse_args(argv)
    base_url = env.get("HYDRA_API_URL") or DEFAULT_API_URL
    try:
        client = HydraClient(base_url, _api_key(args, env), transport=transport, sleep=sleep)
    except (ValueError, OSError) as error:
        stderr.write(f"error: {error}\n")
        return 2
    _warn_if_cleartext(client.base_url, stderr)
    try:
        result = args.handler(args, client)
    except ApiError as error:
        _report(error, stderr)
        return EXIT_API_ERROR
    except TransportError as error:
        stderr.write(f"error: {error}\n")
        return EXIT_UNREACHABLE
    except ValueError as error:  # e.g. a `call` path without a leading '/'
        stderr.write(f"error: {error}\n")
        return 2
    stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return _exit_code(args.command, result)
