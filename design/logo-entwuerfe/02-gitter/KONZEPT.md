# 02 – Gittersiegel

## Idee

Ein schwarzes Siegel mit feinem Gravurring, durchstanzt von einem quadratischen Punktgitter, wie
eine Schlüsselrosette aus Lochblech. Das Schlüsselloch ist kein aufgesetztes Symbol, sondern aus
dem Gitter selbst geschnitten: Der Kopf sitzt in einer Gitterzelle und hat genau den Radius, bei dem
die acht nächsten Gitterpunkte eine Stegbreite entfernt liegen. Der Schaft nimmt genau die zwei
mittleren Spalten weg. Dadurch ist die Materialstärke überall gleich, zwischen den Löchern, am
Schlüsselloch und am Ring. Von weitem sieht man ein Schloss, aus der Nähe ein Gitter.

## Warum es zu «Siegel» und zur Quantensicherheit passt

- **Siegel:** runde Scheibe mit Gravurring, gestempelt auf das weisse Icon wie ein Siegel auf Papier.
  Die Form ist eine Schlüsselrosette, also das, was man an jeder Tür als «verschlossen» liest.
- **Gitter = ML-KEM:** Die Post-Quanten-Verschlüsselung von Siegel (ML-KEM-1024) beruht auf
  Gitterproblemen. Ein Angreifer sieht nur Punkte und findet ohne Schlüssel den Weg durch das Gitter
  nicht. Im Logo ist der Zugang (das Schlüsselloch) genau aus dieser Gitterstruktur gebaut.
- **Ruhig und monochrom:** nur Schwarz und Weiss, keine Schrift, keine Verläufe. Das passt zur
  weissen Oberfläche mit schwarzer Schrift.

## Geometrie (alles in `bau_logo.py`, viewBox 1024)

| Grösse | Wert |
|---|---|
| Siegelscheibe | Radius 372 (Durchmesser 744 = 73 % der Fläche) |
| Gitter | Abstand p = 62, Lochradius r = 0.32 p, Stegbreite w = p − 2r = 22.3 |
| Kopf | in einer Zellmitte, R = (√6.5 − 1)·p + r = 115.9 |
| Schaft | Halbbreite s = 0.5 p + r = 50.8, rundes Ende 4 p unter dem Kopf in einer Zellmitte |
| Ausrundung | Kopf/Schaft mit 0.5 r, damit die Ecke gefräst wirkt |
| Ring | aussen 1 w Rand, Ring 0.5 w, innen 1 w bis zu den Löchern |
| Lochfeld | 52 Löcher, symmetrisch zur Scheibenmitte, das Schlüsselloch sitzt optisch leicht über der Mitte |
| App-Icon | Squircle 824 × 824 bei (100,100), kontinuierliche Ecke r = 185.4; Zeichen × 0.64 (Scheibe = 58 % des Körpers); weicher Schatten aus 8 transparenten Lagen, ohne Filter |

## Dateien

- `mark.svg`: nur das Zeichen, schwarz auf transparent (ein einziger Pfad, `fill-rule="evenodd"`)
- `icon.svg`: macOS-App-Icon
- `icon-klein.svg`: optionale Kleinformat-Fassung für die iconset-Slots 16 und 32 px: gleiche Scheibe,
  gleiches Schlüsselloch, ohne Gitter und Ring. Bei 16 px wird das Gitter zu Grau, und das
  Schlüsselloch verliert Kontrast (vergleiche `icon-16.png` mit `icon-klein-16.png`).
- `bau_logo.py`: erzeugt alles neu, `python3 bau_logo.py` (Parameter überschreibbar, z. B. `rr=0.36`)
- PNGs: `icon-1024/128/32/16.png` (auf #EDEDED), `mark-512.png` (auf Weiss), `icon-klein-16/32.png`
