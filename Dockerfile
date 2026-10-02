# syntax=docker/dockerfile:1
#
# Hydra — containerized runtime.
#
# Two stages:
#   1. go-builder  — compiles the Go-based collection tools Hydra can
#      orchestrate, pinned to an explicit released version (never @latest).
#   2. final        — a slim Python runtime with those binaries, nmap,
#      whois, jq, and Playwright/WebKit, running as a non-root user.
#
# See docs/DOCKER.md for the full usage guide, volume layout, the image-size
# investigation, and the network-confinement verification this image was
# built to preserve.

# ---------------------------------------------------------------------------
# Stage 1 — Go tool builder
# ---------------------------------------------------------------------------
FROM golang:1.26.8-trixie AS go-builder

# libpcap-dev: naabu links against libpcap (cgo) for its raw-socket scan
# engine. gcc: the cgo toolchain golang:trixie does not include by default.
# `apt-get upgrade` (Snyk container remediation): the base image's own
# already-installed OS packages (e.g. pcre2, present regardless of what
# this Dockerfile explicitly installs) can lag behind Debian's latest
# published security patches even on a freshly-pulled `trixie` tag —
# upgrading here, not just installing new packages cleanly, is what
# actually picks those fixes up.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
      libpcap-dev \
      gcc \
    && rm -rf /var/lib/apt/lists/*

# GOTOOLCHAIN=local (Phase 11e): every tool is compiled by this image's own,
# current Go patch release. With `auto`, a tool whose go.mod asks for, say,
# go 1.26.0 made Go download exactly that unpatched toolchain, and every
# binary inherited its standard-library advisories. A tool needing a newer
# Go now fails the build loudly instead.
ENV CGO_ENABLED=1 \
    GOBIN=/out/bin \
    GOTOOLCHAIN=local
RUN mkdir -p /out/bin

# The 7 Go tools Hydra orchestrates, each pinned to a real, published
# release (never @latest; see docs/DOCKER.md), and Phase-09-qualified
# (core/provider_qualification.py). Productization Phase 11e: built with
# security floors on their dependencies, not with plain `go install`, so a
# fixed advisory in a shared module (x/crypto, x/net, ...) reaches the image
# without waiting for upstream releases. The script verifies every binary:
# the tool at exactly its pinned version, every floor met. See the script.
COPY docker/build-go-tools.sh /usr/local/bin/build-go-tools.sh
RUN /usr/local/bin/build-go-tools.sh

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
# Keep the container on a stable Python line that is covered by Hydra's
# CI matrix and supported by binary-extension dependencies such as nassl
# (pulled by sslyze). The previous 3.15.0rc1 base made pip resolution fail
# because nassl 5.x had no cp315 distribution.
# Debian 13 (trixie), not 12 (bookworm) (Snyk container remediation):
# trixie is Debian's current stable line, so its packages carry
# meaningfully newer upstream versions (confirmed: openssl 3.5.7 vs
# 3.0.22, glibc 2.41 vs 2.36, pcre2 10.46 vs 10.42) — a large share of
# bookworm's Snyk findings with "no fix available" are exactly this:
# oldstable not receiving a version bump that isn't itself classified
# as a security backport. Verified before switching: image builds,
# `python app.py --help` runs, and the full test suite passes inside
# the built container (2215 passed / 8 skipped, 0 failed) — same as on
# the bookworm build.
FROM python:3.12-slim-trixie AS final

LABEL org.opencontainers.image.title="hydra" \
      org.opencontainers.image.description="Evidence-backed, scope-aware Attack Surface Intelligence control plane" \
      org.opencontainers.image.source="https://github.com/Andres-Montoya-SV/hydra"

# nmap: port_verify's second-opinion scan. jq: an optional plugin.
# libpcap0.8: naabu's runtime shared library (matches the libpcap-dev
# headers it was linked against in the builder stage). libcap2-bin:
# provides setcap, used once below, not needed at runtime. No `whois`
# package: modules/whois.py uses Hydra's own native Python WHOIS client
# (core/collection/whois_client.py), never the system binary — see
# docs/HARDENING_ROUND2_P1.md, Task 2 (the WHOIS_PATH setting this same
# stale belief produced was removed there; this image install was the
# one place the belief survived).
# `apt-get upgrade` here too, same reasoning as the builder stage above —
# this is the runtime image's own OS package set, independently
# vulnerable to the same class of already-installed-package CVEs.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
      nmap \
      jq \
      libpcap0.8 \
      libcap2-bin \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /out/bin/ /usr/local/bin/

# naabu's SYN-scan engine needs CAP_NET_RAW. Grant it to the binary alone —
# not --privileged on the container, not CAP_NET_ADMIN, not a setuid root
# process. Every other tool in this image runs with zero elevated
# capabilities. (naabu is disabled by default; ENABLE_NAABU=true is what
# actually exercises this.)
RUN setcap cap_net_raw+ep /usr/local/bin/naabu \
    && setcap -v cap_net_raw+ep /usr/local/bin/naabu

# Non-root user, created before any application content so every subsequent
# COPY/RUN below can write with the right ownership the first time — a
# trailing `chown -R` over hundreds of MB of venv/browser/source data would
# double that data's footprint (Docker layers are additive diffs; rewriting
# every file's ownership in its own layer duplicates the content, it does
# not mutate it in place). No interactive login is ever needed against this
# account — `docker run`/`docker compose run` always specify the command
# explicitly — but /bin/bash is kept as the shell for `docker compose run
# hydra bash` debugging sessions.
RUN groupadd --gid 10001 hydra \
    && useradd --uid 10001 --gid hydra --create-home --shell /bin/bash hydra

# WebKit's OS-level shared-library dependencies (modules/browser_probe.py's
# one supported engine — Chromium/Firefox are never installed). Split from
# the browser download itself: `playwright install-deps` only touches apt
# packages (must run as root); the actual browser download runs later as
# the non-root user so those files are owned by hydra from creation, not
# chowned after the fact.
RUN pip install --no-cache-dir playwright==1.62.0 \
    && playwright install-deps webkit \
    && pip uninstall -y playwright \
    && rm -rf /var/lib/apt/lists/* /root/.cache

ENV VENV_PATH=/opt/venv \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN mkdir -p "$VENV_PATH" "$PLAYWRIGHT_BROWSERS_PATH" \
    && chown hydra:hydra "$VENV_PATH" "$PLAYWRIGHT_BROWSERS_PATH"

WORKDIR /app
RUN chown hydra:hydra /app

USER hydra

RUN python -m venv "$VENV_PATH"
ENV PATH="$VENV_PATH/bin:$PATH"

# Dependencies before source so `docker build` cache survives source edits.
# requirements-api.txt (fastapi/uvicorn/argon2-cffi/dnspython) was
# missing here — a real, previously-unnoticed gap: neither this image
# nor CI's own `check` job (.github/workflows/ci.yml) ever installed
# it, so every api/*-dependent test (anything gated by
# `pytest.importorskip("fastapi")`, plus tests/test_scan_queue_
# durability.py's real-subprocess kill+relaunch test, which needs
# `uvicorn` specifically) was silently never exercised in ANY CI path —
# only ever run locally, wherever a dev's own venv happened to have the
# API extras installed. Found via a real CI failure
# (`ModuleNotFoundError: No module named 'uvicorn'`), not by inspection.
COPY --chown=hydra:hydra requirements.txt requirements-dev.txt requirements-api.txt requirements-optional.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
         -r requirements.txt \
         -r requirements-dev.txt \
         -r requirements-api.txt \
         -r requirements-optional.txt \
    && playwright install webkit

COPY --chown=hydra:hydra . .

# output/, logs/, reports/ (and recon.db, which lives under output/) are
# meant to be bind-mounted volumes, not image content — see docs/DOCKER.md.

# No fixed ENTRYPOINT: `docker run hydra ...`/`docker compose run hydra ...`
# takes an arbitrary command (`python app.py run -d target.com`,
# `pytest tests/ -q`, `ruff check .`, `bash`) — tying every invocation to
# `python app.py` would make anything else awkward to run in the same
# image. CMD is only the no-argument default.
CMD ["python", "app.py", "--help"]
