#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Build optimised (release) binaries by default. Performance and security
# experiments measure these, and debug Rust is several-fold slower, so release
# is required for representative numbers. Override the profile for development
# with: CARGO_PROFILE=debug scripts/build_all.sh
PROFILE="${CARGO_PROFILE:-release}"

if [[ "$PROFILE" == "release" ]]; then
  cargo build --release --manifest-path "$ROOT/Cargo.toml"
else
  cargo build --manifest-path "$ROOT/Cargo.toml"
fi
