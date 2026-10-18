# Logo-Wettbewerb – Jury (16.10.2026)

Fünf Entwürfe in `design/logo-entwuerfe/`, zwei Juroren (Markenwirkung, Handwerk). Beide wählten **03-monogramm**.

| Entwurf | Summe |
|---|---|
| 03-monogramm | 16 |
| 04-riegel | 13 |
| 01-wachssiegel | 11 |
| 05-kristall | 11 |
| 02-gitter | 9 |

## Juror Markenwirkung (Sieger: 03-monogramm)

- **03-monogramm: 8**  
  + Einziger Entwurf mit echter Markenqualität: eine eigenständige Silhouette (S aus Scheibe und zwei Schnitten), die man nach einem Blick wiedererkennt. Es ist ein einziger Pfad, punktsymmetrisch und sehr ruhig. Im Dock-Mockup neben Safari, Mail, Notes, Passwörter, Terminal, Xcode und Notion hat es die stärkste Präsenz und wirkt wie ein Logo, nicht wie ein Symbol. Es funktioniert bei 16 px und als 18-px-Menüleisten-Template (dort sind nur 03 und 04 noch lesbar) und hält auch invertiert (dunkles Squircle, weisses S, getestet). Der Bezug zum Namen ist direkt (S = Siegel, runder Stempel). Die Geschichte mit zwei Schlössern für das hybride ML-KEM-1024 + X25519 ist eine gute Markenerzählung. Es spielt nicht, sondern wirkt Schweizer Grafik-streng: Das ist cool im richtigen Sinn.  
  − Die liegenden Schlüssellöcher lesen sich nicht als Schlüssellöcher. Kopf Ø 5u zu Schlitz 3u ist ein zu kleines Verhältnis, darum sieht man Leiterbahnen mit Lötpads oder die bekannte Glyphe «zwei Schieberegler/Filter» (Linie mit Knopf an wechselnden Enden). Invertiert wird der Platinen-Eindruck noch stärker. Ein S im Kreis ist ein volles Genre (Krypto-Token, Fintech), die Eigenständigkeit hängt also ganz an den Schnitten. Das Gitter ist unsichtbar (nur das Konstruktionsraster), und vom Siegel bleibt nur die Scheibe ohne Prägerand. Im Icon wirkt die Scheibe mit 58.6 % optisch etwas leichter als die Nachbarn.
- **04-riegel: 6**  
  + Am konsequentesten gebaut: Jede Kante liegt bei 32 px auf dem Pixelraster, bei 16 und 18 px ist es messerscharf. Abstrakt und dadurch eigenständig, mit Schweizer Brutalismus und Gewicht («Block statt Schlösschen»). Die Idee mit der gleichmässigen Fuge ist intellektuell gut.  
  − Was die Konstruktion meint, liest man ohne Erklärung nicht. Man sieht ein H/E-Glyph, ein Split-View- oder Fenster-Layout-Symbol oder ein Puzzle-Gelenk, aber kein Schloss und schon gar kein Siegel (nichts Rundes, nichts Geprägtes). Ein Quadrat im Squircle ist Form in gleicher Form, also schwache Kontur im Tile. Die riesige schwarze Fläche wirkt im Dock wie ein Loch und erinnert an ein Werkzeug zur Fensterverwaltung (Rectangle/Magnet) statt an einen Tresor.
- **01-wachssiegel: 6**  
  + Die Botschaft ist am schnellsten verständlich (Siegel + Schloss), der Name passt wörtlich. Das Handwerk ist sauber: Wulst-Formel, Hohlkehlen am Schlüssellochhals und eine eigene Kleinfassung ohne Perlrand. Im Dock freundlich und eindeutig.  
  − Generisch: Das Schlüsselloch ist das abgenutzteste Sicherheitssymbol, der gewellte Rand ist die bekannte «Verifiziert»-Badge-Form (SF Symbol checkmark.seal, Instagram/X-Haken), der Perlrand wirkt wie Kronkorken oder Münze. Das Ganze hat Etiketten- oder Craft-Bier-Charme statt Kryptografie. Den Gitterbezug (28 Perlen = Polynomring) sieht niemand. Bei 18 px bleibt nur ein Schlüsselloch-Klecks.
- **02-gitter: 5.5**  
  + Die beste Konzepttiefe: Das Schlüsselloch ist wirklich aus dem Gitter geschnitten, mit gleicher Stegbreite überall. Die Euro-Profilzylinder-Form ist konkreter und europäischer als das Standard-Schlüsselloch. Gitter (ML-KEM), Schloss und Siegel-Gravurring sind gleichzeitig da.  
  − Am wenigsten minimalistisch: 52 Löcher, Doppelring und Schlüsselloch. Im Dock liest es sich als Lautsprechergitter oder Abflussdeckel, nicht als Siegel. Bei 32 px wird das Gitter grau, die Kleinfassung muss es weglassen, und dann bleibt nur eine generische Schlüsselloch-Scheibe. Die Identität hängt also gerade am Detail, das klein verschwindet. Die Klugheit der Konstruktion ist unsichtbar, man sieht Punkte um ein Schloss.
- **05-kristall: 5**  
  + Die Integration ist geschickt: Die drei Fugen des Würfels laufen im Schlüssellochkopf zusammen, und der Schaft ist die vordere Kante. Rund trifft eckig. Saubere Grössenstufen mit eigenen 16/32-px-Fassungen.  
  − Ein isometrischer Würfel ist eines der generischsten Tech-Zeichen (Pakete, AR/3D, Krypto, «Secure Container»). Kopf, Schaft und Fugen bilden ein Y oder ein Männchen mit Krawatte. Das Zeichen ist im Tile zu klein (50 % der Breite) und verliert im Dock gegen jedes Nachbar-Icon. Kein Bezug zu «Siegel».

### Verbesserungen für den Sieger

Alles in bauen.py ändern, nicht im SVG. Prototypen dazu liegen in /private/tmp/claude-501/-Users-aralim-Desktop/b9cbdf41-db59-4539-9e1d-f81d64e2d90a/scratchpad/jury-marke/ (varianten.png: a = Ist, b = rk 2.75u, c = rk 3u, d = rk 3u mit Kreismitte x ±2.5u; dock.png, menubar.png, v_c_dark256.png).

1) Schlüssellochkopf vergrössern, das ist die wichtigste Korrektur. Bisher rk = 2.5u (Ø 5u bei Schlitz 3u). Neu rk = 3u, also Kopf Ø 6u = 2 × Schlitz: Das ist das klassische Schlüsselloch-Verhältnis und eine neue saubere Regel statt «Kreis = Bandstärke». Zusätzlich die Kreismitten von (±3u, ±4u) auf (±2.5u, ±4u) ziehen (Variante d), damit der Ring zum Scheibenrand bei etwa 2.8u bleibt statt auf 2.5u zu fallen. Damit kippt die Lesart weg von «Leiterbahn/Schieberegler» hin zu «Schlüsselloch». Das S bleibt klar (geprüft bei 1024, 128 und 32 px).

2) Am Hals (Übergang Schlitz → Kopf) KEINE Ausrundung, die Ecke bleibt scharf. Eine Hohlkehle wäre genau der Teardrop einer Leiterplatte und verstärkt den falschen Eindruck. Auch die spitzen Bandenden an den Schlitzmündungen (oben rechts, unten links) scharf lassen, sie machen den «Schnitt» aus.

3) Nur falls 1) nicht reicht: den Schlitz zum Scheibenrand hin leicht weiten (am Kopf 2.75u, an der Mündung 3.25u, Mittel weiter 3u), wie ein klassischer Schlüsselschaft. Erst testen, denn es nimmt etwas Ruhe.

4) Grösse im Icon: Die Scheibe wirkt mit 58.6 % (u = 23) im Dock neben Notion, Terminal & Co. leichter als die Nachbarn, weil ein Kreis optisch kleiner ist als ein Quadrat gleicher Breite. Für 1024 bis 64 px u = 24 nehmen (Scheibe 504 px, etwa 61 % des Körpers).

5) Eigene Kleinfassungen ins .icns, wie es 04 und 05 vormachen, dann muss u = 23 nicht mehr die Pixelzeilen retten. Bei 16 px die Bänder 2 · 1 · 2 · 1 · 2 px (Scheibe 8 px, Kopf weglassen oder 2 px), bei 32 px 4 · 2 · 4 · 2 · 4 px (Scheibe 16 px, Kopf 4 px). Jede Kante liegt dann auf ganzen Pixeln.

6) Menüleiste: Aus mark.svg ein Template-Bild für das Status-Item ableiten (18 pt, @1x/@2x pixelgerastert). 03 ist eines von nur zwei Zeichen, die bei 18 px noch lesbar sind, das ist ein echter Vorteil für einen Passwort-Manager.

7) macOS-26-Varianten über Icon Composer mit zwei Ebenen (weisses Squircle, schwarzes Zeichen). Die dunkle Variante (Squircle #111, S weiss) ist getestet und trägt. Weil das Zeichen ein einziger Pfad ist, funktionieren Tinted und Clear ohne Zusatzarbeit.

8) Lockup mit Wortmarke «Siegel», an das u-Raster gebunden: Versalhöhe = 13u (Band + Schlitz + Band), vertikal mittig zur Scheibe, Abstand Zeichen–Wort = 5u. Schrift streng grotesk (SF Pro Display Semibold oder Inter Tight Semibold, Laufweite etwa −1 %). Das S in der Wortmarke NICHT durch das Zeichen ersetzen.

9) Der Gitterbezug gehört nicht ins Icon. Er wird als zweites Markenelement in der App sichtbar (siehe graft).

### Ideen aus anderen Entwürfen

Aus 02-gitter: Das Punktgitter wird als zweite Markentextur auf dem gleichen u-Raster wie das S gebaut (Lochabstand = 1 Schlitz). Es erscheint gross und fein im Sperrbildschirm, im About-Fenster, auf dem Notfallkit-PDF und auf der Website, nie im Icon. Dazu die Erzählung «der Zugang ist aus dem Gitter geschnitten». Aus 04-riegel: die pixelexakte Rasterung pro Grösse (1 Modul = 1 px bei 32) und die eigene 16-px-Stufe im .icns. Ausserdem die Riegel-Idee als Mikroanimation beim Entsperren: Beide Schlitze fahren in etwa 200 ms von den Köpfen zum Rand auf bzw. zu, ruhig und ohne Federn, wie zwei Riegel. Aus 01-wachssiegel: der Perlrand als optionaler «Stempel» nur für grosse Formate und Druck (z. B. Notfallkit, Exportbestätigung), dazu der sich weitende Schlüsselschaft als Testoption (Punkt 3). Aus 05-kristall: optische Korrektur pro Grösse (bei 32 px Schlitze relativ breiter, damit sie mindestens 2 volle Pixel bleiben).

## Juror Handwerk (Sieger: 03-monogramm)

- **03-monogramm: 8**  
  + Handwerklich der sauberste Entwurf: ein einziger geschlossener Pfad, klares Massystem 5-3-5-3-5 (drei Bänder, zwei Schlitze), Schlüssellochkreis = Bandstärke, Ring zum Scheibenrand = Schlitzbreite, punktsymmetrisch und damit ohne Korrektur optisch zentriert. Einziger Entwurf, der ohne Kleinformat-Fassung auskommt: bei 32 px gestochen scharfes S, bei 16 px noch klar lesbar. Stärkste Silhouette im Dock-Vergleich und auf dem weissen Sperrbildschirm bei 88 pt (Kreis + S, sofort wiedererkennbar). Das S als Siegel-Monogramm bindet den Namen ein. Lässt sich verlustfrei invertieren (Dunkelmodus getestet: weisses S auf #111 funktioniert) und als Ein-Pfad-Vorlage für Tinted/Mono-Icons nutzen. Am konsequentesten minimalistisch.  
  − Die liegenden Schlüssellöcher lesen sich zuerst als Leiterbahn-Pads/Pins, nicht als Schlüssellöcher; zusammen mit «S in Scheibe» droht der Eindruck Krypto-Coin/Fintech, die Schloss-Bedeutung erschliesst sich erst mit Erklärung. Scheibe mit 58.6 % des Icon-Körpers wirkt neben Apple-Icons etwas klein und leer. Spitze Ecken (ca. 58°) an den S-Enden, wo die Schlitze aus der Scheibe austreten, und harte Sporne am Übergang Schlitz/Kreis. Schlitz bei 16 px = 1.08 px, also nur fast auf dem Pixelraster (leichtes Grau). S-im-Kreis ist ein dicht besetztes Markenfeld, Verwechslungsprüfung nötig.
- **04-riegel: 7**  
  + Beste Pixel-Handwerksarbeit: 16er-Raster, bei 32 px 1 Modul = 1 px, alle Kanten auf dem Pixelraster, eigene 16-px-Fassung auf 8er-Raster, sauber dokumentierte 12 Entwurfsrunden. Gleichmässige Fuge, gefräste scharfe Innenecken, bei 16 und 32 px der schärfste Entwurf. Eigenständig, kein Schlüsselloch-Klischee, wirkt kräftig und ernst.  
  − Schwarzes abgerundetes Quadrat im weissen Squircle = Icon im Icon, die Eckradien sind nicht konzentrisch (Block 48 gegenüber ca. 115, die bei 62 % Massstab konzentrisch wären), wirkt dadurch eingerahmt statt eingesetzt. Semantisch stumm: liest sich als H/Ǝ-Ligatur, Split-View-Symbol oder Schublade, kein Bezug zu Siegel oder Passwort. Sehr hoher Schwarzanteil (ca. 85 %): auf dem weissen Sperrbildschirm bei 88 pt ein dominanter schwarzer Klotz, der die ruhige Oberfläche erschlägt. Links massiv, rechts dünnwandiges C: optisch kippt das Gewicht nach links.
- **05-kristall: 6**  
  + Gute Kleinformat-Arbeit mit eigenen icon-16.svg/icon-32.svg (Fugen bei 32 px auf ca. 1 px korrigiert, Schaft bei 16 px auf genau 2 px gelegt). Die Integration ist klug: die Fugen laufen im Y in den Schlüssellochkopf, der Schaft ist die vordere Kante. Bei 32 px und 88 pt gut lesbar als «verschlossener Körper».  
  − Isometrischer Würfel ist das Blockchain/Paket/AR-Klischee (vgl. SF Symbol shippingbox), liest sich eher als Krypto-Wallet oder Paketdienst als Passwort-Manager. Uneinheitliche Strichlogik: Diagonalfugen 36, Schaft 65 bis 97 breit, dazu eine Mischung aus Radien r32/r16/r14 und scharfen Schlüssellochkanten. Bei 16 px bleibt nur ein Sechseck mit weissem Balken, der Würfel ist weg. Optisch kleinster Entwurf im Dock (50 % Breite), die spitze Sechseck-Silhouette ist unruhiger als die runden und eckigen Nachbarn.
- **01-wachssiegel: 5**  
  + Erzählt den Namen am direktesten, sorgfältig berechneter Wellenrand (280 Bezier-Segmente), klassisches Schlüsselloch gut proportioniert, optische Höhenkorrektur bedacht, eigene Kleinfassung vorhanden. Bei 88 pt und 1024 px angenehm und eindeutig «Siegel + Schloss».  
  − Die gewellte Rosette ist die Form des Verified-Badges, eines Kronkorkens oder Gütesiegels, generisch statt eigen. Der Perlrand aus 28 Punkten wird schon bei 128 px zu Rauschen (Punkte ca. 3 px), bei 32/16 px zum grauen Ring. Kreisrunder Perlrand in welligem Umriss gibt ungleiche Abstände (in den Tälern eng, an den Wülsten weit), das wirkt unruhig. Die Hohlkehlen am Schlüssellochhals sind kleinteilig. Drei Ebenen sind mehr als «sehr minimalistisch»; die Kleinfassung ist nur noch eine generische Schlüsselloch-Scheibe.
- **02-gitter: 3.5**  
  + Intelligente Konstruktion (überall gleiche Stegbreite, Schlüsselloch aus dem Gitter geschnitten), das Profilzylinder-Schlüsselloch ist in Europa sofort als Schloss lesbar, der Gravurring gibt Siegel-Charakter.  
  − Mit Abstand am unruhigsten: 52 Löcher, Doppelring und Schlüsselloch. Liest sich als Lautsprechergitter, Duschablauf oder Mikrofon. Flimmert schon bei 128 px, bei 32/16 px nur noch eine graue Scheibe; das Konzept ist unter ca. 256 px unsichtbar, die Kleinfassung streicht genau das, was den Entwurf ausmacht. Die feine weisse Ringlinie verschwindet unter 128 px. Getreppter, unregelmässiger Umriss des Lochfelds. Passt nicht zu einer weiss/schwarz-minimalistischen Oberfläche und ist auf dem Sperrbildschirm eine graue Punkttextur.

### Verbesserungen für den Sieger

Verbesserungen für 03-monogramm (alles in bauen.py umsetzen, nicht im SVG):

1. Grösse im Icon: U_ICON 23 auf 25 setzen (Scheibe 525 px = 63.7 % des 824er-Körpers). Getestet: im Dock ruhiger und weniger leer, bei 16 px sogar kontrastreicher. Nicht über 26 gehen, sonst wird die schwarze Masse zu schwer. Vergleichsrender: /private/tmp/claude-501/-Users-aralim-Desktop/b9cbdf41-db59-4539-9e1d-f81d64e2d90a/scratchpad/jury-handwerk/t03-varianten.png (u23, u25, u26, dunkel, 16/32 px gezoomt).

2. Eigene 16- und 32-px-Fassung ins .icns (wie bei 04/05): cy und u so verschieben, dass beide Schlitze genau auf ganzen Pixelzeilen liegen (16 px: Schlitz 1 px, Bänder 2 px; 32 px: Schlitz 2 px, Bänder 4 px). Schlüssellochkreise bei 16 px mindestens 2 px weiss lassen. Prüfung per Skript: Anteil halbdeckender Pixel in den Schlitzzeilen = 0.

3. Übergang Schlitz/Schlüssellochkreis: an den vier konkaven Stellen (weisse Seite) eine Ausrundung von r = 0.4 u. Dann liest sich die weisse Form als ein gefrästes Schlüsselloch statt als «Punkt an einer Linie» (Leiterbahn-Pad). Schlitz gerade und 3 u lassen, nicht verjüngen, sonst bricht das 5-3-5-3-5-System.

4. S-Enden: die spitzen Ecken (ca. 58°) dort, wo die Schlitzoberkante aus der Scheibe austritt (oben rechts, gespiegelt unten links), mit r = 0.15 bis 0.2 u minimal brechen. Sie glitzern dann bei 64 bis 128 px nicht mehr und passen zur kontinuierlichen Apple-Rundung. Die stumpfen Gegenecken scharf lassen.

5. macOS 26: als Icon-Composer-.icon in Ebenen bauen (Ebene 1 weisser Hintergrund, Ebene 2 das S als einzelner Pfad, damit Liquid Glass Glanz und Tiefe auf das S legt). Die 12 eingebackenen Schattenlagen entfernen, den Schatten zeichnet das System. Dazu Varianten Dunkel (#111-Fläche, weisses S, getestet) und Mono/Tinted (nur das S). Das klassische .icns aus derselben Quelle erzeugen.

6. Sperrbildschirm 88 pt: eine Marken-Fassung mit enger viewBox (Scheibe füllt die Box) ableiten. Sonst ergibt mark.svg bei 88 pt nur eine 65-pt-Scheibe. Festlegen, ob die Scheibe 88 pt oder z. B. 72 pt in einem 88er-Rahmen misst. Mindestens einen Scheibendurchmesser Weissraum bis zum Passwortfeld. Optionale funktionale Bewegung statt Verspieltheit: beim Entsperren gleiten die beiden Schlitze (Riegel) um 3 u horizontal aus der Scheibe (ca. 180 ms, ease-out), bei falschem Passwort nur ein kurzes Rütteln der Schlitze um 2 px.

7. Menüleiste/Template-Bild (16 bis 18 pt): nur das S als Alpha-Vorlage, ohne Squircle.

8. Vor der Freigabe eine kurze Ähnlichkeitsprüfung gegen S-im-Kreis-Marken machen (Krypto-Tokens, Fintech, Shazam-ähnliche Zeichen).

### Ideen aus anderen Entwürfen

- Von 04-riegel: die Pixel-Disziplin. u so wählen, dass Kanten bei 32 px auf ganzen Pixeln liegen, dazu eine eigene 16-px-Stufe und eine Vergleichsdatei «ohne Kleinfassung» als Beleg. Ausserdem die Erzählung «die Fuge zeigt den Moment des Schliessens»: Sie passt direkt auf die Schlitze von 03 als Riegel und liefert die Idee für die Entsperr-Animation.
- Von 05-kristall: getrennte icon-16.svg/icon-32.svg aus demselben Bauskript plus rendern.sh, dazu der Ordner runden/ für Zwischenstände (gut für Aralims Prozess-Doku).
- Von 02-gitter: das Prinzip «Materialstärke überall gleich». In 03 schon fast erfüllt (Ring 3 u = Schlitz 3 u); nach dem Einbau der Ausrundungen nachmessen.
- Von 01-wachssiegel: die dokumentierte optische Vertikalkorrektur (Schwerpunkt gegen Umrissmitte) als Prüfschritt im Bauskript. Für das punktsymmetrische S ist sie zwar unnötig, aber nützlich, sobald 16/32-px-Fassungen per Pixel-Snapping verschoben werden.
- Kein Entwurf liefert schon Dunkel- und Tinted-Varianten für macOS 26. Das sollte bei allen nachgezogen werden, 03 kann es am billigsten.
