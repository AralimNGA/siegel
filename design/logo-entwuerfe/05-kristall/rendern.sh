#!/bin/zsh
# Rendert den Entwurf.
#   ./rendern.sh            -> endgültige Dateien in diesem Ordner
#   ./rendern.sh <var> <dir> -> Versuchsvariante aus bau.py (VARIANTEN) in <dir>
set -e
R=/private/tmp/claude-501/-Users-aralim-Desktop/b9cbdf41-db59-4539-9e1d-f81d64e2d90a/scratchpad/svg_render
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
