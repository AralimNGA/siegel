# 03 · Schlüssel-S

**Idee.** Eine schwarze Scheibe, ein Siegelstempel, wird von zwei liegenden Schlüssellöchern
angeschnitten: oben von rechts, unten von links. Was an Schwarz übrig bleibt, ist ein S, das Monogramm.
Der Negativraum hat eine doppelte Bedeutung: Die weissen Formen sind Schlüssellöcher und zugleich zwei
Riegel, die von beiden Seiten ins Siegel greifen. Das Zeichen besteht aus einem Kreis, zwei Balken und
zwei kleinen Kreisen, sonst nichts.

**Warum es zu Siegel passt.**
- *Siegel*: Rund wie ein Prägestempel oder ein Siegelring, dazu das S als Monogramm. Ein Siegel
  zeigt, dass etwas verschlossen und unberührt ist, und genau das macht die App.
- *Zwei Schlösser*: Der Notfallschlüssel ist hybrid gesichert (ML-KEM-1024 + X25519) und bleibt sicher,
  solange eines der beiden Verfahren hält. Im Zeichen stehen dafür zwei Schlüssellöcher.
- *Gitter*: Alle Konstruktionspunkte liegen auf einem ganzzahligen Raster. Das verweist leise auf die
  gitterbasierte Kryptografie hinter ML-KEM, ohne Muster oder Punkte ins Bild zu holen.

## Konstruktion (Einheit u)

| Element | Mass |
|---|---|
| Scheibe | Ø 21 u |
| Senkrechte Teilung | 5 · 3 · 5 · 3 · 5: drei schwarze Bänder, zwei Schlitze |
| Schlüssellochkreis | Ø 5 u (gleich stark wie ein Band), Verhältnis Schlitz zu Kreis 3 : 5 |
| Kreismitten | (−3 u, −4 u) und (+3 u, +4 u), also ein 3-4-5-Dreieck mit genau 5 u Abstand zur Mitte |
| Ring um das Schlüsselloch | mindestens 3 u bis zum Scheibenrand (so stark wie ein Schlitz) |
| Ansatz Schlitz am Kreis | 2 u rechts der Kreismitte (36.87°, wieder 3-4-5) |

Das Zeichen ist punktsymmetrisch und damit ohne Korrektur optisch zentriert.

- `mark.svg`: u = 36, Scheibe 756 px, das sind 74 % der Fläche. Ein einziger geschlossener Pfad.
- `icon.svg`: weisser Squircle 824 px bei (100, 100) mit kontinuierlicher Eckkurve (r 185).
  Zeichen mit u = 23, Scheibe 483 px, das sind 58.6 % des Körpers. Der Schatten besteht aus 12 gestapelten
  Konturen mit je 1.4 % Deckkraft, ohne Filter.
- **Kleine Grössen:** u = 23 ist absichtlich so gewählt. Bei 16 px fallen beide Schlitze fast genau
  auf je eine ganze Pixelzeile (Zeilen 6 und 9), deshalb bleibt das S scharf statt grau zu verschwimmen.
  Bei 32 px gilt dasselbe für je zwei Zeilen.

## Dateien

- `bauen.py` ist die Quelle der Wahrheit: Es schreibt `mark.svg` und `icon.svg` und rendert die PNGs
  (`icon-1024/128/32/16.png` auf #EDEDED, `mark-512.png` auf Weiss). Mass ändern, neu bauen, nicht von
  Hand im SVG editieren.
- Erlaubte SVG-Elemente sind nur `svg` und `path` (Bögen als `A`, Ecken als `C`). Es gibt kein
  filter, mask, clipPath und keinen Text.
