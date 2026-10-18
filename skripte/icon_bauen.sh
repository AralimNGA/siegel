#!/bin/bash
# Baut das App-Icon (Icon Composer, macOS 26) aus design/icon-ebene.svg (SPEC §9, design/LOGO.md).
# Aufruf: skripte/icon_bauen.sh <Zielordner>        z. B. build/Siegel.app/Contents/Resources
# Ergebnis im Zielordner: Assets.car + Siegel.icns. Zwischenstand: build/Siegel.icon, build/icon.plist.
#
# icon.json (Messbefund in design/LOGO.md): weisse Füllung, Gruppe ohne Schatten, ohne Glanzkante
# (specular false), Transluzenz aus. Körper, Glas und Schatten des Körpers zeichnet das System.
# Die Ebene ist bereits um 1024/824 vergrössert (design/bauen.py), sie wird unverändert übernommen.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

ZIEL="${1:-}"
[[ -n "$ZIEL" ]] || { echo "Aufruf: skripte/icon_bauen.sh <Zielordner>" >&2; exit 2; }
QUELLE="$ROOT/design/icon-ebene.svg"
BUILD="$ROOT/build"
ICON="$BUILD/Siegel.icon"
LOG="$BUILD/actool.log"

[[ -f "$QUELLE" ]] || { echo "FEHLER: $QUELLE fehlt" >&2; exit 1; }
grep -q 'viewBox="0 0 1024 1024"' "$QUELLE" \
    || { echo "FEHLER: icon-ebene.svg hat nicht die viewBox 0 0 1024 1024 (design/bauen.py neu laufen lassen)" >&2; exit 1; }

rm -rf "$ICON"
mkdir -p "$ICON/Assets" "$ZIEL"
cp "$QUELLE" "$ICON/Assets/logo.svg"
cat > "$ICON/icon.json" <<'JSON'
{
  "fill" : {
    "solid" : "extended-srgb:1.00000,1.00000,1.00000,1.00000"
  },
  "groups" : [
    {
      "layers" : [
        {
          "image-name" : "logo.svg",
          "name" : "logo"
        }
      ],
      "shadow" : {
        "kind" : "none",
        "opacity" : 0.5
      },
      "specular" : false,
      "translucency" : {
        "enabled" : false,
        "value" : 0.5
      }
    }
  ],
  "supported-platforms" : {
    "squares" : [
      "macOS"
    ]
  }
}
JSON

rm -f "$ZIEL/Assets.car" "$ZIEL/Siegel.icns" "$BUILD/icon.plist"
if ! xcrun actool "$ICON" --compile "$ZIEL" --platform macosx --minimum-deployment-target 26.0 \
        --app-icon Siegel --output-partial-info-plist "$BUILD/icon.plist" --target-device mac >"$LOG" 2>&1; then
    cat "$LOG" >&2
    echo "FEHLER: actool ist gescheitert" >&2
    exit 1
fi
# actool meldet Fehler und Warnungen im Ausgabe-Plist, auch wenn es mit 0 endet
if grep -Eq 'com\.apple\.actool\.(document\.)?errors' "$LOG"; then
    cat "$LOG" >&2
    echo "FEHLER: actool meldet Fehler" >&2
    exit 1
fi
if grep -Eq 'com\.apple\.actool\.(document\.)?warnings' "$LOG"; then
    echo "Warnung von actool:" >&2
    sed -n '/warnings/,/<\/array>/p' "$LOG" | sed -n 's/.*<string>\(.*\)<\/string>.*/  \1/p' >&2
fi

for f in Assets.car Siegel.icns; do
    [[ -s "$ZIEL/$f" ]] || { echo "FEHLER: actool hat $f nicht erzeugt" >&2; exit 1; }
done
for k in CFBundleIconFile CFBundleIconName; do
    v="$(/usr/bin/plutil -extract "$k" raw -o - "$BUILD/icon.plist" 2>/dev/null || true)"
    [[ "$v" == "Siegel" ]] || { echo "FEHLER: icon.plist $k = '$v', erwartet Siegel" >&2; exit 1; }
done
echo "Icon: Assets.car + Siegel.icns"
