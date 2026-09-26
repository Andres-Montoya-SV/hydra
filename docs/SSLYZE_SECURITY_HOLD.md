# SSLyze security hold — 2026-09-26

SSLyze execution and automatic installation are temporarily blocked, including
when `ENABLE_SSLYZE=true`. Attempted execution returns an explicit failure;
it must never claim a completed TLS assessment or silently report no findings.
The default Docker image no longer installs SSLyze. Existing JSON parsers and
archived-evidence handling remain available, using cryptography 50.0.1.

## Evidence

- SSLyze 6.3.1 is the newest release returned by PyPI during this review.
- Its package metadata requires `cryptography>=43,<47`.
- pip cannot resolve `sslyze==6.3.1` with `cryptography==50.0.1`.
- Auditing the old complete Docker Python requirement set resolved
  cryptography 46.0.7 and identified these advisories:
  - GHSA-m2h6-j472-rp4c: certificate name-constraint bypass (fixed in 49).
  - GHSA-jwv3-5hgf-82ww: exponential certificate path building (fixed in 49).
  - GHSA-g6cj-pr64-35w5: PKCS#7 decryption oracle (fixed in 50).
  - GHSA-537c-gmf6-5ccf: vulnerable bundled OpenSSL (fixed in 48.0.1).

Upstream advisories:
https://github.com/pyca/cryptography/security/advisories

This is a dependency vulnerability assessment, not a claim that every advisory
is exploitable through Hydra. The certificate-analysis role makes retaining an
unsupported vulnerable dependency an inappropriate default. No advisories are
ignored in the audit; no `--no-deps` installation or metadata override is used.

## Re-enable only through a reviewed change

1. Select an upstream SSLyze version that supports a patched cryptography
   release, and verify the package metadata and clean dependency resolution.
2. Pin both versions; restore the optional requirement and install method.
3. Run the full audit on all Docker Python requirement sets.
4. Restore execution only after parser, scope/SSRF and real isolated TLS tests
   pass against the new binary. Preserve the existing authorization boundary.
5. Update this document and the Docker capability list, and remove the hold
   regression tests only when replaced by the supported-version checks.

The scope-enforcement test still exercises its original code path with a fake
subprocess; it explicitly overrides the hold inside the test only. Separate
regression tests verify that the production hold runs before target discovery
or process execution and that automatic installation cannot restore SSLyze.
There is no environment flag to bypass the hold.
