#!/bin/bash
# Übernimmt die statische libsodium aus Homebrew als Vendor/Clibsodium.xcframework.
# Danach ist der Bau unabhängig von Homebrew (die Bibliothek liegt im Projekt).
# Aufruf: skripte/libsodium_holen.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${LIBSODIUM_PREFIX:-$(brew --prefix libsodium 2>/dev/null || echo /opt/homebrew/opt/libsodium)}"
OUT="$HERE/Vendor/Clibsodium.xcframework"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

[[ -f "$SRC/lib/libsodium.a" && -f "$SRC/include/sodium.h" ]] || { echo "libsodium fehlt unter $SRC (brew install libsodium)"; exit 1; }
lipo -info "$SRC/lib/libsodium.a" | grep -q arm64 || { echo "libsodium.a ist nicht arm64"; exit 1; }
WANT="1.0.22"
HAVE="$(sed -n 's/.*SODIUM_VERSION_STRING "\(.*\)".*/\1/p' "$SRC/include/sodium/version.h")"
[[ "$HAVE" == "$WANT" ]] || { echo "libsodium $HAVE gefunden, erwartet $WANT (SPEC §9). Abbruch."; exit 1; }

STAGE="$(mktemp -d -t siegel_sodium)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/include"
cp -R "$SRC/include/." "$STAGE/include/"
chmod -R u+w "$STAGE/include"
cat > "$STAGE/include/module.modulemap" <<'MAP'
module Clibsodium {
    header "sodium.h"
    export *
}
MAP
cp "$SRC/lib/libsodium.a" "$STAGE/libsodium.a"
chmod u+w "$STAGE/libsodium.a"

rm -rf "$OUT"
xcodebuild -create-xcframework -library "$STAGE/libsodium.a" -headers "$STAGE/include" -output "$OUT" >/dev/null

VERSION="$(sed -n 's/.*SODIUM_VERSION_STRING "\(.*\)".*/\1/p' "$SRC/include/sodium/version.h")"
SHA="$(shasum -a 256 "$SRC/lib/libsodium.a" | cut -d' ' -f1)"
cp "$SRC/LICENSE" "$HERE/Vendor/LIBSODIUM-LICENSE.txt"
cat > "$HERE/Vendor/LIBSODIUM.txt" <<TXT
libsodium $VERSION (statisch, arm64)
Quelle:  $SRC (Homebrew-Bottle)
SHA-256 libsodium.a: $SHA
Übernommen: $(date +%Y-%m-%d) mit skripte/libsodium_holen.sh
Lizenz: ISC, siehe LIBSODIUM-LICENSE.txt
TXT
echo "OK: $OUT (libsodium $VERSION)"
