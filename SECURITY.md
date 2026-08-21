# Security Review Report

## 1. Security Decisions

### Command Execution
- All subprocess calls use `asyncio.create_subprocess_exec` with argument lists — **never** `shell=True`.
- Binary paths are validated via `validate_binary_path()`; absolute paths must exist, be regular files, and be executable. Symlink binaries are rejected.
- Debug logs quote arguments with `shlex.quote()` and redact `-H` header values.

### Input Validation
- Domains validated against RFC 1123-style regex with shell-metacharacter blocklist.
- Target files confined to `project_root` via `confine_path()`.
- Run IDs restricted to `[a-zA-Z0-9_-]{1,64}`.
- Configuration integers bounded (1–10,000 by default; individual settings such as
  `CACHE_TTL_SECONDS` may declare a wider explicit maximum); booleans reject ambiguous values.
- HTTP header names/values validated; CRLF injection in values rejected.

### File Safety
- All writes use `atomic_write_text()` (temp file + rename). The temp filename embeds the
  PID and a random token (`<name>.<pid>.<uuid>.tmp`) rather than deriving it from the
  destination's own suffix, so writing one file can never clobber an unrelated file whose
  real name happens to match that naive temp-name pattern.
- Output paths confined to run directory via `validate_output_path()`.
- Input files limited to 50 MB; line/record counts capped.
- Optional `.bak` backup before overwrite in `safe_write_text()`.

### Logging
- `SecretRedactingFilter` redacts API keys, tokens, bearer auth, cookies, researcher headers,
  and proxy credentials embedded in URLs from log messages. Keyword-tagged value patterns
  (`api_key=`, `token=`, `bearer `, etc.) redact through end-of-line rather than stopping at
  the first whitespace, so trailing same-line content after a credential can't leak.
- `Settings.to_safe_dict()` never logs header values, credentials, or the configured proxy URL.
- Resolved tool binary paths (Homebrew Cellar, `~/go/bin`, etc.) are logged at DEBUG only;
  INFO logs show the tool name and readiness state, not the local install layout.
- The analyst's home directory is collapsed to `~` in sanitized log messages using a
  case-insensitive, path-boundary-aware match (guards against case-insensitive-but-preserving
  filesystems like macOS APFS/Windows leaking a differently-cased home path, and against a
  sibling directory like `~2/...` being mismatched as a subpath of home).

### Local artifact and report hygiene
- `RunSummary.output_dir` (persisted in `summary.json`/`statistics.json`) is stored relative
  to `project_root`, not as an absolute path — avoids embedding the analyst's username/home
  directory in reports that might be shared or attached to a bug bounty submission.
- `ProvenanceRecord.artifact_path` stores only the artifact's filename, never the absolute
  local path.
- Output, logs, reports directories and `recon.db` (+ WAL/SHM sidecars) are created with
  owner-only permissions (`0700`/`0600`).
- HTTP response headers that can carry session/credential material (`Set-Cookie`,
  `Authorization`, `Proxy-Authorization`) are stripped before being persisted into the
  intelligence store or exported reports (`core/parsers/registry.py::_redact_sensitive_headers`).
  Raw per-tool artifacts (e.g. `httpx.json`) still contain the tool's full unredacted output,
  as they would with any recon tool — only the canonical intelligence layer is redacted.

### Operational privacy (`STRICT_OPSEC`)
- Fails closed: refuses to run without a verified `OUTBOUND_PROXY_URL`.
- Suppresses custom/researcher identification headers and uses a generic User-Agent.
- Blocks plugins that perform raw DNS/TCP probing or whose proxy behavior isn't verified
  (dnsx, naabu, port_verify, whois, asn_lookup, katana, hakrawler, gau, waybackurls, nuclei).
- Routes httpx, crt.sh, URLhaus, and the Playwright browser probe through the configured proxy.
- The plugin result cache is keyed on network mode (`strict_opsec` + `outbound_proxy_url`) in
  addition to plugin name and input, so a cached artifact from a direct (non-proxied) run can
  never be silently replayed as a "cache hit" for a later strict-OPSEC run of the same plugin
  against the same input — and vice versa. Without this, the cache would have quietly defeated
  the fail-closed guarantee `STRICT_OPSEC` is meant to provide.
- This is exposure *reduction*, not anonymity — see `README.md` § Strict OPSEC mode for the
  full list of residual risks (proxy operator, ISP, target-side fingerprinting, endpoint
  compromise) that Hydra's application code cannot mitigate.

### Reporting
- HTML output uses `html.escape()` on all dynamic content to prevent XSS in local reports.

### Concurrency
- `asyncio.Lock` protects shared context mutations during concurrent optional plugins.
- Tracked subprocesses terminated on cancellation via `terminate_all_processes()`.

---

## 2. Remaining Limitations

| Risk | Mitigation Status | Notes |
|------|-------------------|-------|
| Large target sets timing out | Partial | Default 300s timeout may be insufficient for 5k+ hosts; increase `TIMEOUT` in `.env` |
| PATH hijacking for bare tool names | Accepted | Use absolute binary paths in production `.env` |
| hakrawler `-insecure` flag | Documented | Disables TLS verification when enabled |
| nuclei active scanning | Disabled by default | Requires explicit `ENABLE_NUCLEI=true` |
| External tool vulnerabilities | Out of scope | Framework invokes tools; keep tools updated |
| Rate limiting to targets | Delegated to tools | httpx/subfinder handle their own rate limits |

---

## 3. Known Trade-offs

- **Targets file confinement**: Files must live inside the project directory. Safer, but less flexible than arbitrary paths.
- **Async subprocess vs streaming**: stdout buffered in memory before atomic write. Simpler and safer; very large outputs could use more memory.
- **Plugin auto-registration**: Importing `modules/` registers all plugins. No runtime loading from user paths (prevents arbitrary code execution).
- **Bare binary names**: Convenient for development; absolute paths recommended for production.

---

## 4. Future Improvements

- [x] SQLite result store with cross-run deduplication (`core/store.py`, `output/recon.db`)
- [ ] Per-stage configurable timeouts (`DNSX_TIMEOUT`, `HTTPX_TIMEOUT`)
- [ ] Chunked/streaming file writes for very large tool output
- [ ] Scope file filtering (in-scope / out-of-scope assets)
- [ ] Optional TLS verification flag for hakrawler
- [ ] Config profiles (`--profile program-name`)
- [ ] Resume interrupted runs from last completed stage

---

## 5. Technical Debt

| Item | Priority | Description |
|------|----------|-------------|
| `datetime.utcnow()` deprecation | Low | Migrate to `datetime.now(timezone.utc)` |
| jq plugin stub | Low | `ENABLE_JQ` configured but no plugin module yet |
| Statistics report path | Low | `statistics.json` write lacks base_dir confinement (writes to configured reports dir only) |

---

## Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|----|------|------------|--------|------------|
| R1 | Command injection via domain input | Low | Critical | Domain regex + metachar blocklist; list-based subprocess |
| R2 | Path traversal via --file or run-id | Low | High | `confine_path()`, run-id pattern validation |
| R3 | Secret leakage in logs | Medium | High | `SecretRedactingFilter`, safe settings dict |
| R4 | XSS in HTML reports | Low | Medium | `html.escape()` on all dynamic fields |
| R5 | Symlink attacks on binaries | Low | High | Reject symlink binaries in `validate_binary_path()` |
| R6 | DoS via oversized input files | Low | Medium | 50 MB file limit, line/record caps |
| R7 | Race on concurrent plugin writes | Low | Medium | Output paths are per-tool files; lock on context state |
| R8 | Resource leak on interrupt | Low | Medium | `terminate_all_processes()` in finally block |
