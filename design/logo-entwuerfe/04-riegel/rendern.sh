#!/bin/zsh
# Baut die SVGs neu und rendert die Pruefbilder. Renderer per $SVG_RENDER ueberschreibbar, sonst
# design/werkzeuge/bin/svg_render (wird bei Bedarf aus skripte/svg_render.swift uebersetzt).
set -e
HIER=${0:A:h}
R=${SVG_RENDER:-$HIER/../../werkzeuge/bin/svg_render}
if [[ -z "$SVG_RENDER" && ! -x "$R" ]]; then
  # Renderer fehlt: aus skripte/svg_render.swift übersetzen (braucht Xcode oder die Command Line Tools)
  [[ -d /Applications/Xcode.app ]] && export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
  mkdir -p "${R:h}"
  xcrun swiftc -O -o "$R" "$HIER/../../../skripte/svg_render.swift"
fi
python3 "$HIER/bauen.py" final "$HIER" >/dev/null
"$R" "$HIER/mark.svg"       "$HIER/mark-512.png"  512  white
"$R" "$HIER/icon.svg"       "$HIER/icon-1024.png" 1024 '#EDEDED'
"$R" "$HIER/icon.svg"       "$HIER/icon-128.png"  128  '#EDEDED'
"$R" "$HIER/icon.svg"       "$HIER/icon-32.png"   32   '#EDEDED'
# 16 px: handoptimiertes Kleinformat (8er-Raster, 1 Modul = 1 px), wie eine eigene icns-Stufe
"$R" "$HIER/icon-klein.svg" "$HIER/icon-16.png"   16   '#EDEDED'
# Vergleich: grosses Icon direkt auf 16 px heruntergerechnet
"$R" "$HIER/icon.svg"       "$HIER/icon-16-ohne-klein.png" 16 '#EDEDED'
