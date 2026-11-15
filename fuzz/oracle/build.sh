#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Builds the differential-fuzzing oracle. Prints the binary's path on the
# last line of output.
#
# Environment:
#   MITHRIL2PQ_ORACLE_CACHE  build directory (default ~/.cache/mithril2pq-oracle)
#   ORACLE_BUILD=docker      build in RUST_IMAGE (default when cargo is absent)
#   ORACLE_BUILD=native      build with the host's cargo
#   RUST_IMAGE               the image for docker builds
set -eu

here=$(cd "$(dirname "$0")" && pwd)
cache=${MITHRIL2PQ_ORACLE_CACHE:-$HOME/.cache/mithril2pq-oracle}
image=${RUST_IMAGE:-rust:1.100.0-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37}
crate=mithril-stm-0.13.0
# crates.io index checksum of mithril-stm 0.13.0.
crate_sha256=e14c3e420cad7c5d74f063dc93388a4f5624ba71980ea524f45f9278d6d984a2

if [ -z "${ORACLE_BUILD:-}" ]; then
	if command -v cargo >/dev/null 2>&1; then ORACLE_BUILD=native; else ORACLE_BUILD=docker; fi
fi

mkdir -p "$cache/dl" "$cache/target" "$cache/cargo-home"
dl="$cache/dl/$crate.crate"
if [ ! -f "$dl" ]; then
	curl -fsSL -o "$dl.part" "https://static.crates.io/crates/mithril-stm/$crate.crate"
	mv "$dl.part" "$dl"
fi
echo "$crate_sha256  $dl" | sha256sum -c - >/dev/null

# Unpack fresh every time so a stale or hand-edited copy cannot leak into
# the oracle; a patch that no longer applies fails the build.
rm -rf "$here/vendor/$crate"
mkdir -p "$here/vendor"
tar -xzf "$dl" -C "$here/vendor"
patch -s -p1 -d "$here/vendor/$crate" <"$here/oracle-internals.patch"

case "$ORACLE_BUILD" in
native)
	CARGO_TARGET_DIR="$cache/target" cargo build --release --locked --manifest-path "$here/Cargo.toml" >&2
	;;
docker)
	docker run --rm --user "$(id -u):$(id -g)" \
		-e CARGO_HOME=/cache/cargo-home -e CARGO_TARGET_DIR=/cache/target \
		-v "$here:/src" -v "$cache:/cache" -w /src \
		"$image" cargo build --release --locked >&2
	;;
*)
	echo "ORACLE_BUILD must be native or docker" >&2
	exit 2
	;;
esac
echo "$cache/target/release/mithril-oracle"
