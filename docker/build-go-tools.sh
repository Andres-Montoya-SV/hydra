#!/bin/sh
# Productization Phase 11e: build the pinned recon tools with security
# floors on their dependencies.
#
# `go install tool@version` builds exactly the tool's own go.sum, so a
# vulnerable dependency (found by the image scan, Phase 11d) stays until
# upstream ships a release. Instead each tool is built from a throwaway
# wrapper module that requires the tool at its pinned release AND the
# fixed minimum versions below. Go's minimal version selection then raises
# only those modules; everything else, and the tool's own code (including
# the version it reports), is exactly the pinned release. Module checksums
# are still verified against the Go checksum database.
#
# A floor is applied only to tools that already depend on that module.
# None of the pinned releases uses `replace` directives (which a wrapper
# would ignore). Checked when the floors were introduced, 2026-10-01.
set -eu

FLOORS="
golang.org/x/crypto@v0.56.0
golang.org/x/net@v0.56.0
golang.org/x/text@v0.39.0
golang.org/x/mod@v0.40.0
github.com/jackc/pgx/v5@v5.9.0
google.golang.org/grpc@v1.83.2
github.com/go-git/go-git/v5@v5.19.2
github.com/antchfx/xpath@v1.3.6
"

version_at_least() {  # $1 >= $2 (Go module versions)
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

# Fails the image build unless the binary was compiled by this image's Go,
# its main module is the tool at exactly the pinned version, and every
# floored module it contains is at or above its floor: verified, never
# assumed.
verify() {
    binary=$1 module=$2 version=$3
    info=$(go version -m "$binary")
    compiled_by=$(echo "$info" | head -n1 | awk '{ print $2 }')
    [ "$compiled_by" = "$(go env GOVERSION)" ] \
        || { echo "$binary: compiled by $compiled_by, not $(go env GOVERSION)" >&2; exit 1; }
    case "$version" in
        v*) echo "$info" | grep -qE "^[[:space:]]+mod[[:space:]]+$module[[:space:]]+$version([[:space:]]|$)" \
            || { echo "$binary: $module is not $version" >&2; exit 1; } ;;
    esac
    for floor in $FLOORS; do
        found=$(echo "$info" | awk -v m="${floor%@*}" '$1 == "dep" && $2 == m { print $3 }')
        if [ -n "$found" ] && ! version_at_least "$found" "${floor#*@}"; then
            echo "$binary: ${floor%@*} $found is below its floor ${floor#*@}" >&2
            exit 1
        fi
    done
}

build() {
    name=$1 module=$2 package=$3 version=$4
    work=$(mktemp -d)
    cd "$work"
    go mod init "hydra.build/$name" >/dev/null 2>&1
    go get "$package@$version"
    # A floor only ever raises: `go get module@version` sets that exact
    # version, and lowering a module the tool already has newer can drag
    # other modules (even the tool itself) down with it.
    for floor in $FLOORS; do
        current=$(go list -m all | awk -v m="${floor%@*}" '$1 == m { print $2 }')
        if [ -n "$current" ] && ! version_at_least "$current" "${floor#*@}"; then
            go get "$floor"
        fi
    done
    go build -mod=mod -o "$GOBIN/$name" "$package"
    cd /
    rm -rf "$work"
    verify "$GOBIN/$name" "$module" "$version"
}

PD=github.com/projectdiscovery
build subfinder "$PD/subfinder/v2" "$PD/subfinder/v2/cmd/subfinder" v2.16.0
build dnsx "$PD/dnsx" "$PD/dnsx/cmd/dnsx" v1.3.1
build httpx "$PD/httpx" "$PD/httpx/cmd/httpx" v1.12.0
build naabu "$PD/naabu/v2" "$PD/naabu/v2/cmd/naabu" v2.6.1
build katana "$PD/katana" "$PD/katana/cmd/katana" v1.7.0
build nuclei "$PD/nuclei/v3" "$PD/nuclei/v3/cmd/nuclei" v3.11.1
# hakrawler's release tag is not semver ("2.1"); Go resolves it to a
# pseudo-version, so only its floors are verified.
build hakrawler github.com/hakluke/hakrawler github.com/hakluke/hakrawler 2.1
