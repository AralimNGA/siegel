# 05 – Kristall: «Versiegelter Würfel»

## Idee

Ein isometrischer Würfel, gezeichnet nur aus drei schwarzen Flächen, die durch weisse Fugen getrennt sind.
Genau in der vorderen Ecke, wo sich die drei Kanten treffen, sitzt der Kopf eines Schlüssellochs. Der Schaft
ist die vordere senkrechte Würfelkante selbst. Er öffnet sich nur ein Stück weit und endet dann. Darunter
bleibt der Würfel geschlossen. Das Zeichen ist also zugleich Würfel und Schlüsselloch: zwei Fugen und ein
Schaft ergeben das «Y» des Würfels, Kopf und Schaft ergeben das Schloss. Rund trifft eckig: der Schlüssel als
einzige weiche Form in einem harten Kristall.

## Warum es zu Siegel passt

- **Siegel:** Der Körper ist unten ungebrochen, also wirklich versiegelt. Zugang gibt es nur durch die eine
  Öffnung im Zentrum, das ist die Logik eines Tresors mit einem einzigen Master-Passwort.
- **Quantensicherheit:** ML-KEM beruht auf Gittern (lattices). Der Würfel ist die Grundzelle eines
  Kristallgitters, und alle Kanten liegen auf dem Isometrie-Raster (30°/90°/150°). Das Schlüsselloch sitzt
  genau im Gitterpunkt.
- **Oberfläche:** Weiss, Schwarz, keine Graustufe, keine Schrift. Die 3D-Wirkung entsteht nur aus Flächen und
  Fugen, ruhig statt verspielt, und passt damit zur App.

## Geometrie (exakt, aus `bau.py`)

Zeichen in der viewBox 0 0 1024 1024: regelmässiges Hexagon mit der Spitze oben, Umkreisradius 400
(800 × 693 Einheiten, 78 % Höhe), Mitte 512/512.
Fugen 36, Kopf r = 80 genau in der Würfelecke, konischer Schaft (65 breit am Kopf, 97 am Fuss), Ende bei y = 764.
Aussenecken r = 32, Fugenmündungen r = 16, Schaftfuss r = 14. Die Schlüssellochkanten bleiben scharf.
App-Icon: Squircle 824 × 824 bei (100, 100) mit kontinuierlicher Ecke (Koeffizienten der Apple-Ecke,
Radius 185.4). Das Zeichen ist auf 0.6 skaliert (58 % der Körperhöhe, 50 % der Breite), der Schatten besteht aus 9 gestapelten
Körperformen mit je 1.1 % Deckkraft (ohne Filter).

## Kleine Grössen

- `icon.svg` → 1024 / 512 / 256 / 128 px.
- `icon-32.svg` → 32 px: optisch korrigiert, mit Fugen 58, Kopf r = 104 und Massstab 0.64, damit
  die Fugen etwa 1 px breit bleiben.
- `icon-16.svg` → 16 px: Unter 1 px wären die Fugen nicht mehr lesbar, darum entfallen sie. Es bleibt das
  Hexagon mit Schlüsselloch: Der Schaft ist auf genau 2 px gelegt (x = 7 bis 9 px), der Kopf auf
  etwa 3.4 px.

Ein `.icns` darf pro Grösse eigenes Bildmaterial enthalten. Für 16 und 32 px gehören deshalb diese
Fassungen hinein.

## Dateien

`mark.svg`, `icon.svg`, `icon-32.svg`, `icon-16.svg` und die PNGs (`icon-1024/128/32/16.png` auf #EDEDED,
`mark-512.png` auf Weiss). Neu bauen: `./rendern.sh`. Die Zwischenstände der Runden liegen in `runden/`
(r1 bis r3: offener Schaft, Stufenschaft, geschlossener Schaft, sechseckiger Kopf; r4 ist der Endstand).
