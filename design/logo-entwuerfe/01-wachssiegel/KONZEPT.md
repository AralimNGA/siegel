# 01 – Wachssiegel

**Idee.** Eine satte schwarze Siegelscheibe, deren Rand wie ausgeflossenes Wachs in sieben weichen
Wülsten liegt, aber streng berechnet ist: r(t) = R · (1 + 0.034 cos 7t − 0.009 cos 14t). Darin ein
Perlrand aus 28 Punkten, wie ihn jeder Siegelstempel und jede Münze trägt, und in der Mitte ein
Schlüsselloch als reiner Negativraum, mit Hohlkehlen am Hals und gerundeten Fusskanten. Drei Ebenen,
von aussen nach innen: Wachs (versiegelt), Perlrand (geprägt, echt), Schlüsselloch (nur mit dem
richtigen Schlüssel).

**Warum es zu Siegel und Quantensicherheit passt.** Ein Siegel ist das älteste Zeichen für
„unversehrt und nur für den Empfänger“, genau das Versprechen eines Tresors (Manipulation erkennen,
Inhalt verschliessen). Der Perlrand ist das Gitter: ML-KEM rechnet im Polynomring
Z_q[X]/(X^256 + 1), dessen Koeffizienten man sich als Punkte auf einem Kreis vorstellen kann
(Multiplizieren mit X dreht sie um eine Stelle weiter, beim Umlauf mit Vorzeichenwechsel); vier Perlen pro Wulst nicken zum Modulrang
k = 4 von ML-KEM-1024. Das Wachs ist das Alte, das Gitter das Neue: ein Siegel für die Zeit nach dem
Quantenrechner.

**Handwerk.**
- Rand als 280 kubische Bezier-Segmente mit exakten Tangenten, die negative 2. Harmonische macht die
  Wülste breit und die Täler knapp. Kamm oben, Tal unten; das Zeichen sitzt 1.2 % R tiefer, damit es
  zwischen Umriss-Mitte (508) und Tintenschwerpunkt (518) optisch ruhig steht.
- Zeichen in `mark.svg`: 74 % der Breite. Im Icon: 60 % des Körpers.
- Icon-Körper: kontinuierliche Ecke (Squircle-Konstruktion, r = 185.4), Schatten aus 8 Lagen mit je
  2.2 % Schwarz, keine Filter. Nur `<path>` mit `fill-rule="evenodd"`.
- **Kleingrössen:** Bei 16/32 px wird der Perlrand zu grauem Rauschen. `icon-klein.svg` lässt ihn
  weg und zeigt Scheibe und Schlüsselloch grösser (macOS erlaubt eigenes Artwork pro Grösse, ins
  `.icns` für 16 und 32 px nehmen). Vergleich: `icon-16.png` gegen `icon-klein-16.png`.

**Dateien.** `mark.svg`, `icon.svg`, `icon-klein.svg`, PNGs; alles aus `bau.py`
(`python3 bau.py --render <svg_render>`), Werte dort ändern, nicht in den SVGs.
