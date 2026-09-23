#!/usr/bin/env python3
"""Throwaway (but kept, per the task's own "commit it under scripts/ if
it has lasting value for the next billing change") diagnostic tool for
"Confirm Wompi Integration Against a Real Sandbox Account" —
docs/PAID_API_DESIGN.md's Task 3 honesty gap: the `wompi_hash` HMAC
mechanism and the webhook payload shape were implemented against
Wompi's OWN DOCS and tested against a real LOCAL STAND-IN
(`tests/_fake_wompi_server.py`), never against an actual webhook Wompi
itself sent.

**What this does, and does not do**: a minimal, dependency-free HTTP
server that captures the RAW request (every header, the exact raw body
bytes) Wompi's webhook delivery sends, and writes each one to its own
timestamped JSON file — nothing more. It does NOT verify the
`wompi_hash` signature, does NOT touch `control_db`, does NOT run any
of `api/routers/subscription.py`'s real matching logic. That's
deliberate: the whole point is to see EXACTLY what Wompi sends, with
zero risk of this diagnostic's own bugs or assumptions shaping what
gets captured. The real comparison (does `verify_webhook_signature`
actually validate a captured `wompi_hash`? does
`find_pending_enrollment_by_email` see the field names it expects?)
happens afterward, offline, against the captured JSON files — never by
trusting a claim that it "worked."

**How to use it** (coordinate the public-URL step with a tunnel tool
of your choice — this script itself only binds locally):

    python3 scripts/capture_wompi_webhook.py --port 8811 --out-dir /tmp/wompi_captures

Then, temporarily, either:
  (a) point the Wompi dashboard's webhook URL at a public tunnel
      (e.g. `ngrok http 8811`) pointed at this script instead of the
      real API, capture one or more real deliveries, then switch the
      webhook URL back to the real API once done; or
  (b) run this alongside the real API behind a reverse proxy that
      forwards a copy of the request to both — only worth the extra
      complexity if capturing losslessly is more important than
      simplicity for a given run.

Every captured request gets HTTP 200 back immediately (Wompi's own
retry-on-non-2xx behavior would otherwise re-deliver and clutter the
capture directory with duplicates of the same real event).

**Never logs, and never needs, `WOMPI_CLIENT_SECRET`** — this script
takes no credentials at all; it is a pure network capture, not a
verifier. Captured files may still contain a real customer's email/name
(`cliente.Nombre`/`cliente.Email` in Wompi's webhook body) — treat the
output directory as sensitive, do not commit captured files, and delete
them once the comparison is done. `docs/PAID_API_DESIGN.md`'s eventual
write-up must redact them before quoting anything.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _CaptureHandler(BaseHTTPRequestHandler):
    out_dir: Path

    def do_POST(self) -> None:  # noqa: N802 - stdlib's own naming convention
        self._capture()

    def do_GET(self) -> None:  # noqa: N802 - some webhook dashboards send a GET ping first
        self._capture()

    def _capture(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length) if content_length else b""

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        headers = dict(self.headers.items())
        raw_body_text = raw_body.decode("utf-8", errors="replace")
        try:
            parsed_json_body = json.loads(raw_body) if raw_body else None
        except json.JSONDecodeError:
            parsed_json_body = None

        record: dict[str, object] = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "path": self.path,
            "headers": headers,
            "raw_body_text": raw_body_text,
            "parsed_json_body": parsed_json_body,
        }

        out_path = self.out_dir / f"{timestamp}.json"
        out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False))

        print(f"[capture] {self.command} {self.path} -> {out_path}", file=sys.stderr)
        print(f"[capture]   headers: {headers}", file=sys.stderr)
        print(f"[capture]   body: {raw_body_text[:500]}", file=sys.stderr)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "captured"}')

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        pass  # suppressed: our own [capture] lines above are the real log


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    # A throwaway local diagnostic tool meant to be reached via an
    # operator-run tunnel (ngrok or similar) — binding to all interfaces
    # is the point, not an oversight.
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104  # nosec B104
    parser.add_argument("--port", type=int, default=8811)
    parser.add_argument(
        "--out-dir",
        type=Path,
        # Explicit, operator-visible default; always overridable, and
        # this script's whole job is writing files, so a temp dir is
        # the right default, not an insecure shortcut.
        default=Path("/tmp/wompi_captures"),  # noqa: S108  # nosec B108
    )
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    _CaptureHandler.out_dir = args.out_dir

    server = ThreadingHTTPServer((args.host, args.port), _CaptureHandler)
    print(
        f"Listening on {args.host}:{args.port}, writing captures to {args.out_dir} "
        "— Ctrl+C to stop.",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
