#!/usr/bin/env bash
# vendor_pq.sh — re-vendor pruned mlkem-native / mldsa-native trees.
#
# Usage (run from repo root):
#   bash tools/vendor_pq.sh mlkem 2.0.0
#   bash tools/vendor_pq.sh mldsa 2.0.0
#
# Downloads the upstream release tarball, verifies SHA256 against the pinned
# hash below, and extracts ONLY the single-compilation-unit C backend
# (no native/ dirs, no default config, no asm). Then rebuild + retest and
# update third_party/<lib>/README.md hashes.
#
# Policy: stable releases only. Pinned hashes updated by a human per version
# (fetch over a trusted connection, cross-check the upstream release page).
set -euo pipefail

LIB="${1:?usage: bash tools/vendor_pq.sh <mlkem|mldsa> <version>}"
VERSION="${2:?usage: bash tools/vendor_pq.sh <mlkem|mldsa> <version>}"
REPO="${LIB}-native"
URL="https://github.com/pq-code-package/${REPO}/archive/refs/tags/v${VERSION}.tar.gz"

case "$LIB/$VERSION" in
  mlkem/2.0.0) TARBALL_SHA256="76bf71771f09a25f30463218974ae10752d72bca34bbc470c7f6f8655f51d622" ;;
  mldsa/2.0.0) TARBALL_SHA256="97a7305c32b62cbcae97891823176e18ca96d9eaafc3728587d75bb113862a40" ;;
  *) echo "no pinned hash for $LIB $VERSION — add it to $0 first"; exit 1 ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
curl -sSL --fail -o "$WORK/pq.tar.gz" "$URL"
echo "$TARBALL_SHA256  $WORK/pq.tar.gz" | sha256sum -c -
tar -xzf "$WORK/pq.tar.gz" -C "$WORK"
SRC="$WORK/${REPO}-${VERSION}/${LIB}"

DEST="third_party/$LIB/$LIB"
rm -rf "$DEST"
mkdir -p "$DEST"
cp "$SRC/${LIB}_native.h" "$SRC/${LIB}_native.c" "$DEST/"
cp -r "$SRC/src" "$DEST/src"
rm -rf "$DEST/src/native" "$DEST/src/fips202/native"

echo "vendored $LIB $VERSION -> $DEST"
echo "next: sha256sum kept files into $DEST/../README.md, then:"
echo "  cmake -S . -B build && cmake --build build -j && (cd build && ctest --output-on-failure)"