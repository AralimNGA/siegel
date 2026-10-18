#!/bin/zsh
# Rendert den Entwurf. Renderer per $SVG_RENDER, sonst design/werkzeuge/bin/svg_render
# (wird bei Bedarf aus skripte/svg_render.swift uebersetzt).
#   ./rendern.sh            -> endgültige Dateien in diesem Ordner
#   ./rendern.sh <var> <dir> -> Versuchsvariante aus bau.py (VARIANTEN) in <dir>
set -e
R=${SVG_RENDER:-${0:A:h}/../../werkzeuge/bin/svg_render}
if [[ -z "$SVG_RENDER" && ! -x "$R" ]]; then
  # Renderer fehlt: aus skripte/svg_render.swift übersetzen (braucht Xcode oder die Command Line Tools)
  [[ -d /Applications/Xcode.app ]] && export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
  mkdir -p "${R:h}"
  xcrun swiftc -O -o "$R" "${0:A:h}/../../../skripte/svg_render.swift"
fi
cd "${0:A:h}"
if [[ -z "$1" || "$1" == final ]]; then
  D="${2:-.}"
  python3 bau.py final "$D"
  "$R" "$D/mark.svg" "$D/mark-512.png" 512 white
  "$R" "$D/icon.svg" "$D/icon-1024.png" 1024 '#EDEDED'
  "$R" "$D/icon.svg" "$D/icon-128.png" 128 '#EDEDED'
  "$R" "$D/icon-32.svg" "$D/icon-32.png" 32 '#EDEDED'   # optisch korrigierte Kleinfassung
  "$R" "$D/icon-16.svg" "$D/icon-16.png" 16 '#EDEDED'   # Kleinstfassung ohne Fugen
else
  python3 bau.py "$1" "$2"
  "$R" "$2/mark.svg" "$2/mark-512.png" 512 white
  for s in 1024 128 32 16; do "$R" "$2/icon.svg" "$2/icon-$s.png" $s '#EDEDED'; done
fi
