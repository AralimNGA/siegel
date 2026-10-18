# 04 – Riegel

**Konzept: «Der vorgeschobene Riegel»**

Ein schwerer schwarzer Block, durch eine einzige weisse Fuge in zwei Teile geteilt: links das Türblatt
mit seinem Riegel, rechts der Rahmen mit dem Schliessblech. Der Riegel ist ganz vorgeschoben und steckt
satt im Rahmen. Die Fuge läuft mit überall gleicher Breite um ihn herum und zeigt so genau den Moment,
in dem etwas zu ist. Zwei Formen greifen ineinander, ein T in einem C: Keine lässt sich ohne die andere
bewegen. Nichts ist Dekoration. Das Zeichen besteht aus zwei Flächen und einer Linie.

## Warum es zu Siegel passt

- **Siegel / Riegel:** Ein Siegel verschliesst so, dass jede Manipulation sichtbar wird, ein Riegel
  verschliesst mechanisch. Das Zeichen zeigt beides. Die Fuge ist so präzise, dass jede Verschiebung
  sofort auffallen würde.
- **Quantensicherheit ohne Klischee:** ML-KEM beruht auf Gittern. Das Zeichen ist streng auf ein
  16 × 16-Raster gebaut, jede Kante liegt auf einer Gitterlinie. Das Gitter ist nicht zu sehen, aber
  es trägt die Form, ähnlich wie das Gitter die Sicherheit trägt. Dazu kommt das Gewicht: ein Block,
  kein Schlösschen.
- **Passt zur Oberfläche:** reines Schwarz auf Weiss, keine Verläufe, ruhig, so streng wie die App selbst.

## Geometrie

- Raster 16 × 16 Module. Fuge 1, Türblatt 7, Riegel 4 hoch und 6 lang (er kreuzt die Mitte),
  Spiel um die Riegelspitze 1, Rahmenwand dahinter 2. Aussenecken als kontinuierliche Kurve
  (1.5 Module), alle Ecken an Fuge und Riegel scharf, wie gefräst.
- `mark.svg`: Modul 48, Zeichen 768 × 768 (75 %). `icon.svg`: Modul 32, Zeichen 512 × 512 auf dem
  weissen Squircle (824, Radius 185.4, kontinuierlich), das sind 62 % des Körpers.
- **Pixelgenau:** Bei 32 px ist 1 Modul genau 1 Pixel, auch bei 64, 128, 256, 512 und 1024 px
  liegt jede Kante auf dem Pixelraster. Keine Kante ist halb deckend.
- **16 px:** `icon-klein.svg` ist dasselbe Zeichen auf einem 8er-Raster (1 Modul = 1 px), wie eine
  eigene Stufe im .icns. `icon-16.png` stammt daraus. Zum Vergleich zeigt `icon-16-ohne-klein.png`
  das grosse Icon, einfach verkleinert: Dort wird die Fuge grau.
- Nur `path`/`g`, `fill-rule="evenodd"`, Schatten aus halbtransparenten Squircles, keine Filter.

## Dateien

`bauen.py` erzeugt alle SVGs aus der Geometrie, `rendern.sh` baut neu und rendert die PNGs.
In `runden/` liegen die Entwurfsrunden: 1–3 Falz, Querriegel, S-Haken; 4–7 Rahmen, Schieber,
Querbalken; 8 Verzahnung; 9–12 Rasterfassung und Feinabstimmung.
Verworfen wurden: runde Riegelspitze (sieht aus wie ein Puzzleteil), Querbalken mit Rahmen (wirkt wie
ein Kettenglied oder ein Drucker), S-Fuge (ist ein Buchstabe und deckt sich mit 03-monogramm),
Knauf (zu bildhaft).
