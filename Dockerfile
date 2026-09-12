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
FROM golang:1.25.14-bookworm AS go-builder

# libpcap-dev: naabu links against libpcap (cgo) for its raw-socket scan
# engine. gcc: the cgo toolchain golang:bookworm does not include by default.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcap-dev \
      gcc \
    && rm -rf /var/lib/apt/lists/*

ENV CGO_ENABLED=1 \
    GOBIN=/out/bin \
    GOTOOLCHAIN=auto
RUN mkdir -p /out/bin

# Every version below is pinned to a real, currently-published release tag,
# confirmed buildable before being pinned here (see docs/DOCKER.md) — the
# exact 7 Go tools this task named, not Hydra's full optional tool roster
# (gau/waybackurls/assetfinder/unfurl/anew/amass), kept out deliberately to
# hold the image size down; add more with the same pattern if needed.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.16.0
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@v1.7.0
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1
RUN go install -v github.com/hakluke/hakrawler@2.1

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS final

LABEL org.opencontainers.image.title="hydra" \
      org.opencontainers.image.description="Evidence-backed, scope-aware Attack Surface Intelligence control plane" \
      org.opencontainers.image.source="https://github.com/Andres-Montoya-SV/hydra"

# nmap: port_verify's second-opinion scan. whois: modules/whois.py. jq: an
# optional plugin. libpcap0.8: naabu's runtime shared library (matches the
# libpcap-dev headers it was linked against in the builder stage).
# libcap2-bin: provides setcap, used once below, not needed at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap \
      whois \
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
COPY --chown=hydra:hydra requirements.txt requirements-dev.txt requirements-optional.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
         -r requirements.txt \
         -r requirements-dev.txt \
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
