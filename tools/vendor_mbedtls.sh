#!/usr/bin/env bash
# vendor_mbedtls.sh — re-vendor a pruned mbedTLS tree.
#
# Usage (run from repo root):
#   bash tools/vendor_mbedtls.sh 3.6.4
#
# Downloads the upstream release tarball, verifies its SHA256 against the
# pinned hash below, and extracts ONLY the keep-list (compiled sources +
# needed headers + public include/ + LICENSE). Then rebuild + retest and
# update third_party/mbedtls/README.md hashes.
#
# Policy: LTS versions only. The pinned TARBALL_SHA256 must be updated by a
# human for each new version (fetch it over a trusted connection and
# cross-check against the upstream release page); never blindly accept.
set -euo pipefail

VERSION="${1:?usage: bash tools/vendor_mbedtls.sh <version, e.g. 3.6.4>}"
URL="https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v${VERSION}.tar.gz"

# Pinned tarball hashes (version -> sha256).
case "$VERSION" in
  3.6.4) TARBALL_SHA256="a1e01f6094bb744ead8caaa92d7c7102b7137a813f509b49afaebc0b8e51899c" ;;
  *) echo "no pinned hash for $VERSION — add it to $0 first"; exit 1 ;;
esac

KEEP_C="aes.c block_cipher.c constant_time.c gcm.c platform.c platform_util.c"
KEEP_H="common.h alignment.h block_cipher_internal.h constant_time_internal.h constant_time_impl.h ctr.h"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
curl -sSL --fail -o "$WORK/mbedtls.tar.gz" "$URL"
echo "$TARBALL_SHA256  $WORK/mbedtls.tar.gz" | sha256sum -c -
tar -xzf "$WORK/mbedtls.tar.gz" -C "$WORK"
SRC="$WORK/mbedtls-$VERSION"

DEST="third_party/mbedtls"
rm -rf "$DEST"
mkdir -p "$DEST/library" "$DEST/include"
for f in $KEEP_C $KEEP_H; do cp "$SRC/library/$f" "$DEST/library/$f"; done
cp -r "$SRC/include/." "$DEST/include/"
cp "$SRC/LICENSE" "$DEST/LICENSE"

echo "vendored $VERSION -> $DEST"
echo "next: sha256sum the kept files into $DEST/README.md, then:"
echo "  cmake -S . -B build && cmake --build build -j && (cd build && ctest --output-on-failure)"