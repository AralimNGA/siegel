#!/bin/zsh
# Baut die SVGs neu und rendert die Pruefbilder. Renderer per $SVG_RENDER ueberschreibbar.
set -e
HIER=${0:A:h}
R=${SVG_RENDER:-/private/tmp/claude-501/-Users-aralim-Desktop/b9cbdf41-db59-4539-9e1d-f81d64e2d90a/scratchpad/svg_render}
python3 "$HIER/bauen.py" final "$HIER" >/dev/null
"$R" "$HIER/mark.svg"       "$HIER/mark-512.png"  512  white
"$R" "$HIER/icon.svg"       "$HIER/icon-1024.png" 1024 '#EDEDED'
"$R" "$HIER/icon.svg"       "$HIER/icon-128.png"  128  '#EDEDED'
"$R" "$HIER/icon.svg"       "$HIER/icon-32.png"   32   '#EDEDED'
# 16 px: handoptimiertes Kleinformat (8er-Raster, 1 Modul = 1 px), wie eine eigene icns-Stufe
"$R" "$HIER/icon-klein.svg" "$HIER/icon-16.png"   16   '#EDEDED'
# Vergleich: grosses Icon direkt auf 16 px heruntergerechnet
"$R" "$HIER/icon.svg"       "$HIER/icon-16-ohne-klein.png" 16 '#EDEDED'
