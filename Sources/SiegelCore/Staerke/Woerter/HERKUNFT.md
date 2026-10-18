# Wortlisten der Passwort-Schätzung – Herkunft, Lizenzen, Prüfung

Stand 17.10.2026 (Befunde #18, #44, #49 eingearbeitet). Gehört zu SPEC §1.6 (`PasswordStrength`, `MasterPasswordPolicy`, `PassphraseGenerator`).

## Erzeugen

```
python3 skripte/woerter/listen_bauen.py      # aus dem Paketordner, nur Standardbibliothek, kein Netz
```

Das Skript liest `skripte/woerter/quellen/` und `/usr/share/dict/web2` und schreibt die Dateien
`Liste*.swift` in diesen Ordner. Jede Liste ist **ein** Raw-String-Literal (eine Zeile je Eintrag), das zur
Laufzeit einmalig in ein `Dictionary<String, Int>` (Wort → Rang) geladen wird. Keine Array-Literale, damit die
Typprüfung nicht explodiert. Die Ausgabe ist deterministisch. Die `Liste*.swift` nie von Hand ändern.

Regeln des Generators:
- Alles NFC und kleingeschrieben; Steuer- und Richtungszeichen werden verworfen.
- Rang = Zeilennummer (1 = häufigst). Bei eigenen deutschen Listen stehen Umschriften mit gleichem Rang
  in derselben Zeile, durch Tabulator getrennt (`müller\tmueller\tmuller`, `ß → ss`, `é → e`, Punkt/Bindestrich
  entfernt: `st.gallen → stgallen`).
- Wie zxcvbn: Einträge, die als Brute-Force billiger wären (Rang ≥ 10^Länge), entfallen. Deshalb stehen kurze,
  wichtige Einträge (Vereinskürzel `yb`, `fcb`, Kantonskürzel, `ich`, `du`) am Anfang ihrer Liste.
- Passphrasen-Liste: Abbruch, wenn nicht **genau 2048** Wörter, nicht `^[a-z]{4,8}$`, doppelt, oder wenn ein
  gesperrter Wortstamm vorkommt (Schimpfwörter, Gewalt, Drogen, Religion …; `barsch` wurde deshalb durch
  `seide` ersetzt).
- web2: nur Wörter ab 6 Buchstaben (kürzere wären als Brute-Force billiger), nur a–z, nur solche, die in keiner
  anderen Liste stehen; alphabetisch und vorn-komprimiert (erstes Zeichen = Länge des gemeinsamen Anfangs mit
  dem Vorgänger, 0–9/a–z).

## Listen

| Swift-Literal | Quelle | Lizenz | Zeilen | Rang |
|---|---|---|---|---|
| `passwords` | zxcvbn 4.4.2 `passwords.txt` (Xato/Burnett 10 Mio.) | MIT (zxcvbn), Rohdaten frei veröffentlicht | 30 000 | Zeile |
| `passwordsGerman` | eigene Liste `passwoerter_de.txt` (DE/CH-Passwörter, Wendungen) | eigenes Werk | 1 063 | Zeile |
| `englishWikipedia` | zxcvbn `english_wikipedia.txt` | MIT (zxcvbn); Zählungen aus Wikipedia | 30 000 | Zeile |
| `usTvAndFilm` | zxcvbn `us_tv_and_film.txt` | MIT (zxcvbn); Häufigkeiten aus Wiktionary | 19 160 | Zeile |
| `englishWeb2` | macOS `/usr/share/dict/web2` (Webster's 2nd Int. 1934) | gemeinfrei | 194 043 | uniform 150 000 |
| `germanWords` | eigene Liste `woerter_de.txt` | eigenes Werk | 4 368 | Zeile |
| `surnames`, `maleNames`, `femaleNames` | zxcvbn (US-Volkszählung 1990) | MIT (zxcvbn); Rohdaten gemeinfrei | 10 000 / 984 / 3 712 | Zeile |
| `firstNamesCHDE`, `surnamesCHDE` | eigene Listen `vornamen_ch_de.txt`, `nachnamen_ch_de.txt` | eigenes Werk | 439 / 308 | Zeile |
| `placesCH` | eigene Liste `orte_vereine_ch.txt` (Orte, Kantone + Kürzel, Fussball- und Eishockeyvereine CH/DE, Berge, Seen, Flüsse, DE/AT-Städte) | eigenes Werk | 547 | Zeile |
| `passphraseWords` | eigene Liste `passphrase_de.txt` | eigenes Werk | 2 048 | uniform 2 048 |

Insgesamt 293 957 Schlüssel, 1.98 MB Quelltext (davon web2 1.11 MB). Gemessen (Release, M5 Max): Laden 31 ms,
+14.5 MB Arbeitsspeicher.

**zxcvbn-Daten**: nicht heruntergeladen, sondern lokal übernommen aus der Chrome-Komponente
`~/Library/Application Support/Google/Chrome/ZxcvbnData/3/` (Chrome liefert damit die Originallisten von
zxcvbn aus). Unverändert kopiert nach `skripte/woerter/quellen/zxcvbn/` samt `LIZENZ.txt` (MIT-Hinweis, muss in
die Lizenzhinweise der App: vollständiger Wortlaut in `LIZENZEN.md` im Paketordner, von dort zeigt ihn die
Oberfläche an; Befund #44). SHA-256:

```
f65b16793f0d335c87bf5bb4b19bcfc457462396169080b8c11a7c6f1d8b3731  passwords.txt
b29af10c62218f948eb299e0c68b176ab1c5ecdfe9813bd957bf2c434e90813e  english_wikipedia.txt
f146e15ecba3f37adcd7aa4fb23797555d1ab55489fbb0b989c60073f638aaa0  us_tv_and_film.txt
3362648c77af4ee84a6383800fb5a5cb0493703d4bfc1557e05f315fc41b2699  surnames.txt
34519e42ef61ea5eae6b9f74a735926c86ed8d1c19d21726da1af6039a66c688  male_names.txt
08346ad80d8d829fda1064485420da1e0771ba1e0dcd954252d43b61c5116aaf  female_names.txt
```

**Eigene Listen**: aus eigenem Wissen von Hand zusammengestellt (Orientierung an öffentlich bekannten
Auswertungen wie den jährlichen Top-Listen des HPI Potsdam, Namensstatistiken, Vereinsnamen), keine Kopie
einer fremden Liste. Die Reihenfolge ist eine grobe Häufigkeitsschätzung; der Rang wirkt nur logarithmisch.
Ergänzen: Wort in die passende Datei unter `skripte/woerter/quellen/` schreiben, Skript laufen lassen, testen.

## Bewertung

`PasswordStrength.estimate` ist zxcvbn 4.4.2 (Dropbox) in Swift: Muster Wörterbuch (mit Rang), umgekehrt (×2),
l33t (`@4→a, 3→e, 1!|→i/l, 0→o, $5→s, 7→t, 9→g`), Gross-/Kleinschreibung, Tastaturfolgen (QWERTY, QWERTZ-CH mit
`<>`-Taste, Ziffernblock PC und Mac; Graphen in `Zxcvbn/KeyboardGraphs.swift` selbst aufgebaut),
Wiederholungen, Folgen, Jahre 1900–2099, Daten, Benutzereingaben; Brute-Force 10 je Zeichen; minimale Zerlegung
per dynamischer Programmierung mit `g = l!·Π guesses + 10000^(l−1)`, `bits = log2(g)` (in log2 gerechnet,
kein Überlauf). Analysiert werden höchstens die ersten 256 Zeichen; bei längeren Eingaben deckelt die Periode der
ganzen Eingabe die Schätzung (siehe „Kürzung“ unten).

Fünf **Siegel-Erweiterungen** (nicht in zxcvbn; sie können Schätzungen nur senken, denn die Zerlegung nimmt
immer das Minimum):

1. **Passphrase aus der eigenen Liste**: k Wörter der 2048er-Liste (auch mit l33t-Ersetzungen) kosten
   `2048^k · Trennstücke · Schreibweise · l33t`. Reines zxcvbn gab einer gekürzten Passphrase mit 4 Wörtern
   69 Bit, obwohl sie nur 44 Bit Zufall hat; jetzt 48 Bit (abgelehnt). 6 Wörter: 70 Bit.
2. **Wortfolge mit Trennzeichen** (`Mein Hund heisst Bello`): reines zxcvbn bewertet jedes Wort und jedes
   Leerzeichen einzeln (×10000 je Teil) und kam so auf 63.7 Bit. Ein Angreifer probiert Wortfolgen nach dem
   Produkt P der Ränge; es gibt etwa `N(P) = P·(ln P)^(k−1)/(k−1)!` Folgen mit kleinerem Produkt. Geschätzt
   wird `N(P) · Trennstücke · Schreibweise`; Läufe sind Buchstaben- bzw. Ziffernfolgen, unbekannte Wörter
   zählen wie Brute-Force (10^Länge), Ziffern wie Jahr bzw. 10^Länge. Ergebnis 54.5 Bit (abgelehnt).

3. **Zähler-Vorlage** (Befund #18, `Zxcvbn/ZxcvbnVorlagen.swift`): Jeder maximale Ziffernlauf wird zum Platzhalter;
   eine Vorlage mit genau einem Platzhalter, die sich mindestens zweimal wiederholt und deren Zahlen eine
   arithmetische Folge mit Schritt ±1, ±2, ±5 oder ±10 bilden (auch `01 02 03`, auch abgebrochen am Ende), ist ein
   Teilstück. Kosten: Grundwort (kleinste Zerlegung der Vorlage ohne Zahl) · 10^Breite der Startzahl · 8 Schritte ·
   Lage der Zahl in der Vorlage · Zahl der Wiederholungen.
4. **Kalenderfolge** (Befund #18): aufeinanderfolgende Wochentage oder Monate (19 Reihen: Kurz- und Langformen
   DE/EN/FR/IT, Nebenformen wie `mar`/`maer` für März), ab beliebigem Start, vorwärts oder rückwärts, über das Ende
   hinweg, mit überall gleichem Trennstück. Kosten: Reihen · Start · Richtung 2 · Trennstück · Schreibweise ·
   Länge (+1 Bit für Nebenformen).
5. **Ort + Postleitzahl** (Befund #18): Ort aus `placesCH` direkt vor oder nach einer vierstelligen Zahl 1000–9699
   (wahlweise mit einem Trennzeichen) ist ein Teilstück; mehrere solche Einheiten gleicher Form hintereinander
   ebenfalls, ohne den Zuschlag 10000 je Teil. Kosten: Rang des Orts · Schreibweise · Postleitzahl (87, wenn sie auf
   `00` endet wie die Hauptnummern der Städte, sonst 8700) · Form (Reihenfolge, Trennzeichen) · Trennstück.

Gemessen vorher → nachher (Befund #18; vorher alle von `create` angenommen):

| Passwort | vorher | nachher | Zerlegung nachher |
|---|---|---|---|
| `Hund1Hund2Hund3Hund4Hund5Hund6` | 88.8 | 18.8 | counter |
| `Basel1Basel2Basel3Basel4` | 65.1 | 17.9 | counter |
| `Bello1Bello2Bello3Bello4` | 69.9 | 23.2 | counter |
| `Katze1Katze2Katze3Katze4Katze5` | 79.1 | 18.8 | counter |
| `Basel4000Bern3000Zürich8000` | 68.5 | 47.8 | placeCode (Kette) |
| `Thun3600Bern3000Biel2500` | 70.2 | 48.4 | placeCode (Kette) |
| `Mo-Di-Mi-Do-Fr-Sa-So`, `Mo.Di.Mi.Do.Fr.Sa.So` | 64.4 | 15.9 | calendar |
| `Lu-Ma-Me-Je-Ve-Sa-Di` | 65.3 | 15.9 | calendar |
| `Jan.Feb.Mar.Apr.Mai.Jun` | 74.2 | 17.4 | calendar |
| `Jan-Feb-Mar-Apr-May-Jun` | 74.2 | 16.4 | calendar |

Der übliche Ablauf aus dem Befund („Hund1…Hund4“ wird abgelehnt, also „Hund5“ anhängen) führt jetzt nicht mehr zum
Erfolg: Hund1…Hund4 18.2 Bit, Hund1…Hund6 18.8 Bit. Die Gegenproben (300 generierte 6-Wort-Passphrasen,
2000 × 20 Zufallszeichen, die 30 typischen Passwörter) sind unverändert.

**Kürzung** (Befund #49): Analysiert werden die ersten 256 Zeichen. Muster über die Grenze hinaus sieht die
Zerlegung nicht; das kann die Schätzung auch **erhöhen** (z. B. ein zweimal getipptes langes Passwort: 33×a 33×b
33×c 33×d doppelt ergab 93.0 statt 41.5 Bit). Darum bestimmt `PasswordStrength.periodicCap` bei Kürzung die
längste periodische Anfangsfolge der ganzen Eingabe (KMP-Präfixfunktion, O(n)) und nimmt
`Schätzung(Periode) + log2(Länge/Periode)` (ein Rest danach zählt wie ein zweites Teilstück: 2·g1·g2 + 10000) als
Deckel, wenn das weniger ist. Das Beispiel ergibt jetzt 41.5 Bit.

**Trennstücke** (beide Erweiterungen, seit Befund #17 vom 16.10.2026): zwischen zwei Wörtern 0–3 Zeichen, die
keine Buchstaben sind. Überall gleich: ein häufiges Zeichen (`Leerzeichen - _ . , ; : / + * | ~ # ! ?`) oder
keins = 16 Varianten; übliche Muster aus 2–3 häufigen Zeichen (`, `, ` - `, `--`, zwei Leerzeichen) = 16 · 5;
sonst Zeichen für Zeichen (häufig 15, Ziffer 10, übriges ASCII 33, Rest 128 Varianten). Je Lücke verschieden:
das Günstigere aus „jede Lücke für sich“ und „Grund-Trennstück mit einzelnen Abweichungen“. Vorher erkannten
die Erweiterungen nur genau ein, überall gleiches Zeichen ohne Ziffern; `kerze, vulkan, flaute, pirat` kam so
auf 78.3 Bit, `kerze1vulkan2flaute3pirat` auf 69.2, `k3rze-vulk4n-fl4ute-pir4t` auf 72.2 (alle angenommen).
Jetzt 50.3, 58.0 und 52.0 Bit. 2000 zufällige 4-Wort-Passphrasen mit `, ` erreichen höchstens 50.3 Bit; generierte
6-Wort-Passphrasen mit ` - ` mindestens 70.7 Bit; 20 Zeichen Zufall unverändert.

Generierte 6-Wort-Passphrasen: über 20 000 Stichproben mindestens 63.8 Bit (0.1-%-Quantil 68.8, Median 70).
Sechs der häufigsten Listenwörter (`hallo-keller-fischer-frei-schatz-ernst`) ergäben nur 36.7 Bit; das ist
extrem selten (0 von 2 Mio. simuliert unter 60), `PassphraseGenerator.generate` zieht dann trotzdem neu.

**Stufen** (`Level`): `veryWeak` < 28 Bit (≈ 2.7·10^8 Versuche), `weak` < 36, `fair` < 60, `strong` < 80,
`veryStrong` ≥ 80. Die Master-Passwort-Regel verlangt ≥ 60 Bit = mindestens `strong`, dazu ≥ 12 Zeichen und
≤ 1024 UTF-8-Bytes, geprüft nach der Abbildung aus §1.1 (Zs → Leerzeichen, NFC). Benutzereingaben: `siegel`,
`NSUserName()`, `NSFullUserName()`, deren Teile, zusammengeschrieben und mit Umschrift.

**Laufzeit** (Release, M5 Max): 64 Zeichen höchstens 1.1 ms (200 zufällige: max. 0.7 ms); Extremfälle mit
256 Zeichen 10–22 ms (l33t-Mehrdeutigkeit `1!|l…`, 51× dasselbe Listenwort `hund-hund-…`); 1000 Zeichen 4 ms
(analysiert werden nur die ersten 256). Vorgabe < 20 ms für 64 Zeichen (Test `laufzeit64Zeichen`, im Release-Build
mit Grenze 20 ms, im Debug-Build 150 ms).

## Prüfung gegen die Intuition: 30 typische Passwörter

Erzeugt mit `SIEGEL_STAERKE_TABELLE=1 swift test --filter StaerkeTypischTests` (Bezugsjahr 2026; zuletzt
abgeglichen am 17.10.2026 – drei Zeilen hatten noch Werte von vor Befund #17). „Intuition“ =
grobe eigene Erwartung vor dem Messen. Alle 30 werden von der Master-Passwort-Regel abgelehnt (< 60 Bit).

| Gruppe | Passwort | Bit | Stufe | Zerlegung | Intuition | Urteil |
|---|---|---|---|---|---|---|
| Verein+Jahr | `YB1898` | 9.4 | veryWeak | dictionary(YB1898) | < 20 | passt |
| Verein+Jahr | `FCBasel1893!` | 18.8 | veryWeak | dictionary(FCBasel1893) bruteforce(!) | < 25 | passt |
| Verein+Jahr | `scbern2026` | 15.2 | veryWeak | dictionary(scbern) year(2026) | < 22 | passt |
| Verein+Jahr | `EHCBiel2025!` | 27.3 | veryWeak | dictionary(EHCBiel) year(2025) bruteforce(!) | < 30 | passt |
| Verein+Jahr | `HCDavos1921` | 21.9 | veryWeak | dictionary(HCDavos) year(1921) | < 30 | passt |
| Verein+Jahr | `BVB09Dortmund` | 16.8 | veryWeak | dictionary(BVB09) dictionary(Dortmund) | < 30 | passt |
| Name+Jahr | `Michael1985` | 13.9 | veryWeak | dictionary(Michael) year(1985) | < 22 | passt |
| Name+Jahr | `Sabine1972!` | 25.5 | veryWeak | phrase(Sabine1972) bruteforce(!) | < 30 | passt |
| Name+Jahr | `Lukas2008` | 13.9 | veryWeak | dictionary(Lukas) year(2008) | < 22 | passt |
| Name+Jahr | `LaraMüller2010` | 26.7 | veryWeak | dictionary(Lara) dictionary(Müller) year(2010) | < 32 | passt |
| Name+Jahr | `Thomas.Meier1979` | 15.4 | veryWeak | phrase(Thomas.Meier) year(1979) | < 36 | passt (seit Befund #17 als Wortfolge erkannt) |
| Name+Jahr | `Jürg1965!` | 23.1 | veryWeak | phrase(Jürg1965) bruteforce(!) | < 30 | passt |
| Tastatur | `qwertz123` | 5.4 | veryWeak | dictionary(qwertz123) | < 15 | passt |
| Tastatur | `1qay2wsx` | 5.2 | veryWeak | dictionary(1qay2wsx) | < 15 | passt |
| Tastatur | `asdfghjklöä` | 12.1 | veryWeak | spatial(asdfghjklöä) | < 18 | passt (QWERTZ-CH) |
| Tastatur | `yxcvbnm,.-` | 12.0 | veryWeak | spatial(yxcvbnm,.-) | < 18 | passt (QWERTZ-CH) |
| Tastatur | `147258369` | 5.4 | veryWeak | dictionary(147258369) | < 15 | passt |
| Tastatur | `+"*ç%&/()=` | 13.0 | veryWeak | spatial(+"*ç%&/()=) | < 18 | passt (Umschalt-Ziffernreihe CH) |
| Satz | `IchLiebeMeinenHund` | 22.0 | veryWeak | dictionary(IchLiebeMeinenHund) | < 40 | passt (Wendung in Liste) |
| Satz | `Mein Hund heisst Bello` | 54.5 | fair | phrase(Mein Hund heisst Bello) | < 58 | passt; reines zxcvbn: 63.7 |
| Satz | `DieSonneScheintHeute!` | 52.6 | fair | dictionary(Die) dictionary(Sonne) dictionary(Schein) bruteforce(tHeute!) | < 55 | knapp |
| Satz | `ichgehejetztnachhause` | 48.1 | fair | bruteforce(ichgehe) dictionary(jetzt) dictionary(nach) dictionary(hause) | < 55 | passt |
| Satz | `Ich wohne seit 2015 in Olten` | 53.3 | fair | phrase(Ich wohne seit 2015 in Olten) | < 58 | passt (Ort am 19.10.2026 neutral ersetzt; reines zxcvbn dafür nicht neu gemessen) |
| Satz | `EsWarEinmalEinKönig1990` | 30.6 | weak | dictionary(EsWarEinmalEinKönig) year(1990) | < 45 | passt (Wendung in Liste; ohne: 60.3) |
| Sonstiges | `Sommer2025!` | 15.2 | veryWeak | dictionary(Sommer2025) bruteforce(!) | < 22 | passt |
| Sonstiges | `Grüezi123` | 16.8 | veryWeak | dictionary(Grüezi) sequence(123) | < 22 | passt |
| Sonstiges | `Zürich2026` | 14.5 | veryWeak | dictionary(Zürich) year(2026) | < 22 | passt |
| Sonstiges | `P@ssw0rt!` | 13.4 | veryWeak | dictionary(P@ssw0rt) bruteforce(!) | < 20 | passt |
| Passphrase (4 Wörter) | `kerze-vulkan-flaute-pirat` | 48.0 | fair | passphrase(kerze-vulkan-flaute-pirat) | 44 Bit Zufall | passt; reines zxcvbn: 69.2 |
| Passphrase (englisch) | `correcthorsebatterystaple` | 48.0 | fair | dictionary(correct) dictionary(horse) dictionary(battery) dictionary(staple) | ≈ 44 (XKCD) | passt |

Erkenntnisse aus der Prüfung (eingearbeitet): kurze Vereins- und Kantonskürzel fielen zuerst durch den
zxcvbn-Filter (Rang ≥ 10^Länge) und stehen jetzt vorn; Sätze und gekürzte Passphrasen wurden überschätzt
(siehe Erweiterungen); häufige deutsche Wendungen (`eswareinmal`, `ichliebedich` …) stehen in der Passwortliste.

## Grenzen (ehrlich)

- Kein Sprachmodell: Sehr lange natürliche Sätze (8+ Wörter) gelten als stark (z. B. `Ich bin heute mit dem
  Hund im Wald gewesen` ≈ 86 Bit), obwohl ein Angreifer mit Grammatikmodell schneller wäre.
- Wörter ausserhalb der Listen zählen als Brute-Force (10 je Zeichen); seltene deutsche Wörter, Dialekt und
  Komposita werden darum eher überschätzt. Die eigene deutsche Liste hat rund 4 400 Wörter.
- Ort + Postleitzahl: Es gibt keine eingebaute PLZ-Tabelle. Die Zahl kostet darum immer 87 bzw. 8700 Varianten,
  auch wenn sie wirklich zum Ort gehört (ein Angreifer mit Tabelle bräuchte nur wenige). Ketten aus drei Orten mit
  ihren Hauptnummern liegen so bei rund 48 Bit (abgelehnt), ab vier Orten über 60 (`Thun3600Bern3000Biel2500Basel4000`
  62.2 Bit) – für frei gewählte Paare aus 547 Orten und 87 Hauptnummern wäre das sogar zutreffend.
- Zähler-Vorlagen verlangen eine wörtlich gleiche Vorlage (gleiche Gross-/Kleinschreibung) und genau eine Zahl je
  Wiederholung: `Hund1hund2hund3hund4` wird nur ab der ersten Zahl erkannt (25.7 Bit), `a1b1a2b2` gar nicht.
  Kalenderfolgen kennen nur DE/EN/FR/IT.
- Bei Kürzung wird nur eine periodische **Anfangs**folge erkannt; eine Wiederholung, die erst nach einem Vorspann
  beginnt (`x` + B + B mit |B| > 128), kann weiterhin überschätzt werden. Das ist bei über 256 Zeichen selten.
- Zufällige 20 Zeichen aus 94 liegen fast immer bei 66.4 Bit; in etwa 1 von 20 000 Fällen findet die Schätzung
  ein Wort im Zufall (z. B. `lISA`) und landet knapp unter 60.
