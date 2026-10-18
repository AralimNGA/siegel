# Prüfbericht – Fuzzer, Sanitizer, Python-Gegenprobe (Siegel, SPEC v4.2, v4.4 und v4.5 §21)

Stand: 17.10.2026. Gerät: MacBook Pro M5 Max (18 Kerne, 48 GB), macOS 26.7 (25G229), Xcode 27, Apple Swift 6.4
(swiftlang-6.4.0.34.1). Alle Läufe mit `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.

Runde 1 (§1–§6, SPEC v4.2, Nacht auf den 17.10.): Fuzzer, Sanitizer und Gegenprobe neu aufgebaut und lange gefahren.
**Runde 2 (§7, SPEC v4.4, 17.10. vormittags): Abschluss nach den Befunden der zweiten Prüfung** – 38 Befunde in
7 Dimensionen behoben, danach alles erneut gefahren: 487 Tests grün, Gegenprobe, 10-min-Fuzz-Rauchtest, ASan + TSan,
204 Snapshots, Bau und Start – ohne Fund.
**Runde 3 (§8, SPEC v4.5, 17.10. nachmittags und abends): Selbstvernichtung im Fuzzer** – neues Ziel `vernichtung`,
fünf Vernichtungs-Saaten, Abbruch-Zeitpunkte in `ctaphid`, Einspielen in `sicherung`; beim Aufbau 8 Fehler im
Produktcode gefunden und behoben (je mit Regressionstest); 16 von 17 Wirksamkeitsproben gefunden, eine aus
nachvollziehbarem Grund nicht; Langlauf mit neuer Saat: 12 Ziele, 8.5 Fuzz-Stunden, 58.1 Mio. Eingaben – ohne Fund;
Abschluss: 496 Tests grün, ASan + TSan ohne Meldung, Gegenprobe, Bau und Start.

## Ergebnis in Kürze (Runde 1)

| Prüfung | Umfang | Ergebnis |
|---|---|---|
| Fuzzer `SiegelFuzz` (AddressSanitizer) | 10.1 Fuzz-Stunden, 136.2 Mio. Eingaben, 11 Ziele, 3 Läufe | **kein Fund im Produktcode**: kein Absturz, kein Hänger, keine ASan-Meldung, keine manipulierte Datei geöffnet, keine verletzte Invariante |
| Wirksamkeit des Fuzzers | 7 absichtlich eingebaute Fehler | 5 gefunden (1–183 s), 2 aus nachvollziehbaren Gründen nicht (§1.5) |
| `skripte/sanitizer.sh address` | `swift test`, 402 Tests | bestanden, 0 Meldungen |
| `skripte/sanitizer.sh thread` | `swift test`, 402 Tests | bestanden, 0 Meldungen |
| `referenz/gegenprobe.sh` | v1 + v2 Beispieldatei, 119 Prüfpunkte | alles stimmt |
| `referenz/differenz.sh` (neu) | 2300 Mutanten der Beispieldateien | keine Abweichung, Python öffnet keinen Mutanten |
| `swift test` | 402 Tests (308 Kern/Werkzeuge, 94 Hardware) | grün, 0 Warnungen |
| `./build.sh` | Grep-Sperren, Release, Signatur, 6 Entitlements, Installation | grün |

Behoben wurden nur Dinge in der Testumgebung und in den Prüfwerkzeugen selbst (§1.4, §2.2). Der Produktcode
(SiegelCore, SiegelHardware, SiegelUI) ist unverändert.

## 1. Fuzzer `SiegelFuzz`

### 1.1 Aufbau

- Ausführbares Ziel `SiegelFuzz` (nur im Debug-Bau, `@testable import` für den DEBUG-KDF-Testschalter und die internen
  Parser; im Release-Bau gibt es nur einen Hinweis aus). Eigenes Werkzeug ohne Fremdbibliothek: libFuzzer liefert Apples
  Werkzeugkette nicht mit (`-sanitize=fuzzer` → „unsupported option“, gemessen).
- **Rückkopplung**: neue Kanten über SanitizerCoverage (`-sanitize-coverage=edge,trace-pc-guard`, Rückrufe im kleinen
  C-Ziel `SiegelFuzzAbdeckung`, 96 071 instrumentierte Kanten) und neue Ergebnis-Codes. Lauf 1 hatte nur die
  Ergebnis-Codes, Lauf 2 beides.
- **Strukturbewusst**: Saat sind 7 Tresore über die öffentliche Schnittstelle (Stufen 1–5, Faktoren nur für Einträge,
  versiegelte Einträge Schutz 2–5, Credential 16/48/1024 Byte, Verlauf, Gelöschtes, TOTP), dazu eine im Speicher
  gebaute v1-Datei (alle mit Testschalter-KDF; die Tresore entstehen in einem Temp-Ordner, der danach gelöscht wird),
  und die beiden eingefrorenen Beispieldateien (echtes Profil 256 MiB). Mutationen kennen alle Felder von Kopf v1/v2,
  Slots und Inhalt: Grenzwerte (Version, KDF, Maske, Schema, Credential-Länge, Generation, ctLen), Maske mit passenden
  Feldern, Credential-Länge mit Einfügen/Entfernen, Kürzen/Einfügen an Feldgrenzen, Abschnitte aus anderen Tresoren,
  Polster-Bereich des Chiffrats; danach Prüfsumme meist neu berechnet (Angreifer), sonst alt, mit falschem
  Versions-Label oder zufällig.
- **Ziele und Invarianten** (Einzelheiten in `Sources/SiegelFuzz/FUZZ-NOTIZEN.md`):

| Ziel | Was | Kern-Invarianten |
|---|---|---|
| `datei` | Tresordatei v1/v2 | jede Datei ≠ Saat öffnet nie (Passwort + Faktoren, Notfallweg mit Entsiegeln); Prüfsumme zuerst (unabhängig nachgerechnet); Fehler nur feste `SiegelError`; nur Inhalt geändert → `corruptFile`; Kopf unverändert → nie `wrongRecoveryCode` (§1.3) |
| `inhalt` | Inhalts-JSON, mit dem DEK neu verschlüsselt | Fehler nur `corruptFile`; Lesen → Schreiben → Lesen gleich; direkter Weg = Dateiweg; `UnlockedVault`, Bericht, Aufdecken aller Einträge, Notfallweg ohne Absturz |
| `notfall` | Notfallcode und Teile | ≤ 2 ersetzte Zeichen, Nachbartausch, ≤ 4 „?“ werden immer gefunden, mit genau den Stellen; Treffer passen zum Kopf; Fehler nur aus der festen Menge |
| `karte` | QR-Inhalt/abgetippte Karte | nur Gültiges wird angenommen, harmlose Schreibweisen immer, fremde Kartenversionen nie |
| `csv` | CSV-Import, Export → Import | Fehler nur `csvInvalid` mit festem Code und plausibler Zeile; alle Grenzen; Rundlauf Feld für Feld |
| `totp` | otpauth-URI, Base32, Code | feste Codes; Grenzen; `digits` Ziffern, 1 ≤ Rest ≤ Periode auch für ±∞/NaN/vor 1970; URI-Rundlauf |
| `cbor` | CBOR, getInfo, authenticatorData, COSE | kanonischer Rundlauf; Fehler nach aussen nur `factorUnavailable`/`factorCancelled`/`crypto("fido.input")` |
| `ctaphid` | Reassembler, Zerlegen, ganze FIDO2-Abläufe gegen ein gestörtes Gerät | Fristen halten; ungestört genau HMAC(credRandom, Salz); Fehler nach aussen nur `factorUnavailable`/`factorCancelled` |
| `hwdatei` | `<keyID>.siegelhw` (§14.1) | nur mit gültiger Prüfsumme, Art und keyID; bytegleich neu kodierbar |
| `sicherung` | Namen am zweiten Sicherungsort, Ausdünnung | Namen-Rundlauf; nie angeheftete/älteste löschen; deterministisch |
| `autofill` | `AutofillMatcher` (§20) | harmlose Varianten passen immer, Phishing-Varianten nie, nie http für https |

- **Wächter**: Signal-Handler sichern die laufende Eingabe bei Swift-Laufzeitfehler, `abort` (auch nach einem
  ASan-Bericht), SIGILL/SIGFPE; ein Wächter-Thread beendet bei Überschreiten des Zeitlimits pro Eingabe (5–60 s je
  Ziel, unter ASan ×4) mit Exit 77 und sichert die Eingabe. Funde ohne Absturz werden als `fund-*.bin/.txt` gesichert.
- **Bau** (in `skripte/fuzz.sh`):
  `swift build -c debug --product SiegelFuzz -Xswiftc -sanitize=address -Xswiftc -Xllvm -Xswiftc -asan-globals=0
  -Xswiftc -sanitize-coverage=edge,trace-pc-guard --scratch-path .build/fuzz-asan`.
  Ohne `-asan-globals=0` scheitert der Bau reproduzierbar am Linker (`ld: Assertion failed: (name.size() <= maxLength)`
  beim Bau von SiegelCore.o; Ursache: die Wortlisten-Literale um 1 MB plus Redzone). Heap, Stack und
  use-after-return bleiben geprüft.
- **Reproduzierbar**: Saat-Zahl protokolliert; Saat-Tresore liegen in `build/fuzz/saat/` (SHA-256 im Protokoll);
  Eingaben aus SplitMix64; gesicherte Eingaben mit `skripte/fuzz.sh --wiederholen <datei> <ziel>` einspielbar
  (geprüft, siehe §1.5). Ausgaben enthalten nur Zähler, Codes und Prüfsummen, keine Eingaben oder Geheimnisse.

### 1.2 Läufe

Alle Ziele parallel, je Ziel die volle Laufzeit. Saat-Korpus in allen Läufen gleich
(`t1 46c1ca7f…, t1e e49a1e16…, t2 ae5c3996…, t3 30f8d68a…, t4 78bb200a…, t5 6b53ca1f…, t5l 12fe0306…, v1t 67932e56…`).

**Lauf 1** – Saat `1792198534`, 9 Ziele, ASan, Rückkopplung nur über Ergebnis-Codes, 02:55–03:25
(Binärdatei `e019d88f…`). Die Zusammenfassung von `fuzz.sh` brach am Ende ab, weil ich das Skript während des Laufs
geändert hatte (Bash liest Skripte stückweise; alle neun Ziele endeten mit Exit 0). Zahlen aus `<ziel>.json`:

| Ziel | Minuten | Eingaben | pro s | Ergebnisarten | Funde | Exit | langsamste Eingabe (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| `datei` | 30.0 | 1'326'441 | 737 | 7551 | 0 | 0 | 0.97 |
| `inhalt` | 30.0 | 842'505 | 468 | 13 | 0 | 0 | 1.94 |
| `notfall` | 30.0 | 41'007 | 23 | 17 | 0 | 0 | 2.41 |
| `karte` | 30.0 | 6'951'285 | 3'862 | 3 | 0 | 0 | 0.16 |
| `csv` | 30.0 | 85'969 | 48 | 17 | 0 | 0 | 0.94 |
| `totp` | 30.0 | 4'485'697 | 2'492 | 16 | 0 | 0 | 0.14 |
| `cbor` | 30.0 | 8'102'418 | 4'501 | 81 | 0 | 0 | 0.12 |
| `ctaphid` | 30.0 | 70'383 | 39 | 747 | 0 | 0 | 0.82 |
| `hwdatei` | 30.0 | 32'996'459 | 18'331 | 9 | 0 | 0 | 0.14 |
| **Summe** | **4.50 h** | **54'902'164** | | | | | |

(Die hohe Zahl Ergebnisarten bei `datei` kam von Zahlen in Fehlercodes wie `unsupportedVersion(513)`; für Lauf 2 werden
solche Zahlen zusammengefasst, damit sie den Korpus nicht verdrängen.)

**Lauf 2** – Saat `17102026`, 11 Ziele, ASan + Kanten-Abdeckung, 03:32–04:02 (Binärdatei `63acaa8e…`):

| Ziel | Minuten | Eingaben | pro s | Ergebnisarten | Kanten (neu im Lauf) | Funde | Exit | langsamste Eingabe (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `datei` | 30.0 | 1'065'527 | 592 | 34 | 4774 (+843) | 0 | 0 | 0.70 |
| `inhalt` | 30.0 | 309'266 | 172 | 13 | 8825 (+1458) | 0 | 0 | 4.38 |
| `notfall` | 30.0 | 35'692 | 20 | 17 | 2637 (+1333) | 0 | 0 | 2.16 |
| `karte` | 30.0 | 5'889'497 | 3'272 | 3 | 1048 (+618) | 0 | 0 | 0.10 |
| `csv` | 30.0 | 94'079 | 52 | 17 | 1826 (+1570) | 0 | 0 | 0.84 |
| `totp` | 30.0 | 3'990'133 | 2'217 | 16 | 1271 (+1015) | 0 | 0 | 0.14 |
| `cbor` | 30.0 | 8'556'488 | 4'754 | 81 | 1402 (+894) | 0 | 0 | 0.14 |
| `ctaphid` | 30.0 | 59'795 | 33 | 100 | 2300 (+755) | 0 | 0 | 0.82 |
| `hwdatei` | 30.0 | 28'299'912 | 15'722 | 9 | 799 (+375) | 0 | 0 | 0.11 |
| `sicherung` | 30.0 | 16'374'657 | 9'097 | 6 | 1102 (+665) | 0 | 0 | 0.13 |
| `autofill` | 30.0 | 15'506'542 | 8'615 | 4 | 733 (+478) | 0 | 0 | 0.14 |
| **Summe** | **5.50 h** | **80'181'588** | | | | | | |

„Kanten“ zählt alle erreichten Kanten des Prozesses (Saat-Erzeugung und Selbsttest eingeschlossen), „neu im Lauf“
die während des Fuzzens dazugekommenen. Dazu kommen ein Probelauf von 30 s je Ziel (Saat 4242, 9 Ziele) und nach den
letzten Änderungen (nur Ausgabeformat) eine Schlussprobe von 15 s je Ziel mit dem endgültigen Stand (Saat 5,
11 Ziele, ASan + Abdeckung): ebenfalls 0 Funde.

Ausgewählte Zähler aus Lauf 2: `datei` hat 4790 Mutanten der Beispieldateien mit neuem Salz voll durchgerechnet
(Argon2 256 MiB) und 5123 mit anderen KDF-Parametern im erlaubten Bereich übersprungen (Argon2 bis 4 GiB; die
Testschalter-Saaten decken diese Mutationen ab); 17 034 Mutationen ergaben zufällig wieder die Saat und öffneten
erwartungsgemäss. `inhalt` hat 45 594 gültige Inhalte über den ganzen Weg geführt (Datei, Passwortweg,
`UnlockedVault`, Bericht, Aufdecken, Notfallweg); beim Aufdecken manipulierter versiegelter Einträge kamen nur
`wrongPassword` (5074), `wrongCard` (681) und `factorUnavailable(.secureEnclave)` (107, ungültiger ephemerer Schlüssel).
`ctaphid`: 19 850 ungestörte Registrierungen/Ausgaben endeten mit genau der richtigen HMAC-Ausgabe, 2534 gestörte
gelangen trotzdem, alle übrigen gestörten Abläufe endeten innerhalb der Fristen mit `factorUnavailable` bzw.
`factorCancelled`.

### 1.3 Summe je Ziel (alle Läufe)

| Ziel | Stunden | Eingaben | Funde |
|---|---:|---:|---:|
| `datei` | 1.01 | 2'412'153 | 0 |
| `inhalt` | 1.01 | 1'167'272 | 0 |
| `notfall` | 1.01 | 77'568 | 0 |
| `karte` | 1.01 | 12'973'134 | 0 |
| `csv` | 1.01 | 181'299 | 0 |
| `totp` | 1.01 | 8'567'528 | 0 |
| `cbor` | 1.01 | 16'862'239 | 0 |
| `ctaphid` | 1.01 | 131'143 | 0 |
| `hwdatei` | 1.01 | 61'970'261 | 0 |
| `sicherung` | 0.50 | 16'374'657 | 0 |
| `autofill` | 0.50 | 15'506'542 | 0 |
| **Summe** | **10.08** | **136'223'796** | **0** |

### 1.4 Funde und Behebungen

**Produktcode: keine Funde.** Kein Absturz, kein Hänger, keine Sanitizer-Meldung, keine Datei ≠ Saat geöffnet (weder
über Passwort und Faktoren noch über den Notfallweg, auch nicht mit neu berechneter Prüfsumme), keine falsche
Fehlerart, keine verletzte Rundlauf- oder Korrektur-Eigenschaft. Darum gibt es keine neuen Regressionstests für den
Produktcode; die Wirksamkeit der Orakel ist in §1.5 belegt.

Befunde in den Prüfwerkzeugen (beim Bau des Fuzzers, alle behoben, jeweils danach erneut gefahren):

1. Kern verlangt Argon2-Pfade ausserhalb des Main-Threads (`dispatchPrecondition`): Der Fuzzer lief zuerst auf dem
   Main-Thread und stürzte in der Saat-Erzeugung ab (libdispatch-Trap ohne Text). → eigener Arbeits-Thread mit 256 MiB
   Stapel.
2. CBOR-Baumgenerator wuchs exponentiell (Felder mit 300 Elementen, rekursiv): Hänger im Generator. → breite Felder
   nur mit Blättern.
3. Karten-Generator ersetzte `1` durch `l` auch im Präfix (`SIEGELKARTEl:`); der Kern lehnte zu Recht ab. → Präfix
   und Code getrennt umschreiben.
4. Geräte-Emulator meldete `maxMsgSize` 1200 bei 1024 Byte Credential; die Plattform lehnte zu Recht mit
   `unsupported("msgsize")` ab (schon bei der Registrierung, also kein späteres Aussperren). → Emulator meldet eine zur
   Credential-Länge passende Grösse.
5. Inhalt-Ziel: 77 % der Mutationen waren Typfehler (`payload.json`), weil Behälter oft ganz ersetzt wurden. →
   typtreue Mutationen, Behälter-Ersatz nur noch zu 3 %.
6. Geänderte Compiler-Flags machten `.build/fuzz-asan` nicht ungültig (alte Objekte ohne `-asan-globals=0` wurden
   weiterverwendet, Bau scheiterte). → `fuzz.sh` merkt sich die Flags und baut bei Änderung neu.
7. `fuzz.sh` während Lauf 1 geändert → Zusammenfassung brach ab (Daten blieben erhalten). Hinweis in FUZZ-NOTIZEN.md.
8. Zahlen in Fehlercodes (`unsupportedVersion(n)`, `hidError(n)`) blähten die Ergebnisarten auf. → zusammengefasst.
9. Ausgabe von `--wiederholen` war bei Codes mit Anführungszeichen kein gültiges JSON. → `JSONSerialization`.

### 1.5 Wirksamkeitsproben

Damit „keine Funde“ etwas aussagt, habe ich typische Fehler vorübergehend in den Kern eingebaut, den Fuzzer (Debug-Bau
ohne ASan, Saat 99) kurz gefahren und die Dateien danach zurückgesetzt (SHA-256 vor/nach verglichen: gleich).

| Eingebauter Fehler | Ziel | Ergebnis |
|---|---|---|
| Datei-Prüfsumme wird nicht verglichen (`VaultFile.verifyChecksum`) | `datei` | gefunden nach 3 s / 2 Eingaben: „Datei mit falscher Prüfsumme wurde gelesen“ |
| Restbytes nach dem Chiffrat erlaubt (`r.remaining >= ctLen`) | `datei` | gefunden nach 1 s / 102 Eingaben: „manipulierte Datei öffnet über den Passwortweg“ |
| Fehlerkorrektur prüft bei 2 Fehlern die letzte Stelle nicht | `notfall` | gefunden nach 183 s / 4233 Eingaben: „korrigierbarer Code nicht gefunden“ |
| CSV-Import entfernt Steuerzeichen im Titel nicht | `csv` | gefunden nach 1 s / 226 Eingaben |
| Autofill vergleicht Suffix ohne Punkt (`evilbank.ch` für `bank.ch`) | `autofill` | gefunden nach < 1 s / 110 Eingaben: „Phishing-Variante passt“ |
| Generation nicht in der AD des Inhalts | `datei` | schon der Selbsttest scheitert (die Saat-Dateien öffnen nicht mehr); als Mutationsfund nicht messbar, weil jede Änderung der AD alle bestehenden Dateien bricht |
| Fehlerkorrektur ohne eigenen Nachbartausch | `notfall` | nicht gefunden – kein Verhaltensunterschied: Die Stufe „2 ersetzte Zeichen“ findet jeden Nachbartausch ebenfalls |

Nebenbei belegt: Eine Probe mit ungültigem Bereich (`(i + 1)..<(n - 1)`) stürzte ab; der Wächter sicherte die Eingabe
(`absturz-notfall-<pid>.bin`, 73 Byte), und `--wiederholen` spielte sie mit dem korrigierten Code ohne Absturz ein.
Ebenso liefen die gesicherten Fund-Eingaben der Proben nach dem Zurücksetzen sauber durch.

### 1.6 Grenzen (ehrlich)

- libsodium (vorübersetzt) und die System-Frameworks (CryptoKit, Foundation) sind nicht instrumentiert; ASan läuft ohne
  Globals-Instrumentierung. Speicherfehler dort fände nur ein Absturz, nicht ASan.
- Abdeckung zählt nur das erste Erreichen einer Kante (keine Trefferhäufigkeit wie bei AFL) und nur Swift-Code.
- Mutanten der echten Beispieldateien mit anderen KDF-Parametern im erlaubten Bereich werden nicht voll gerechnet
  (Argon2 bis 4 GiB); diese Fälle decken die Testschalter-Saaten ab.
- FIDO2 nur gegen den eigenen Geräte-Emulator, nicht gegen Hardware; Emulator und Plattform teilen die PIN/UV-Krypto
  (für Robustheit unerheblich; unabhängige Gegenseite haben die bestehenden `VirtualAuthenticator`-Tests).
- Nicht gefuzzt: die Oberfläche (SiegelUI), die Kamera-/Vision-Erkennung der QR-Karte (Bilder), Dateisystem-Abläufe
  (Speichern, Sicherungen einsetzen) – die prüfen die Unit-Tests.
- Der Korpus wird zwischen Läufen nicht aufbewahrt, nur die Saat.

## 2. Sanitizer (`skripte/sanitizer.sh`)

### 2.1 Ergebnis

| Lauf | Dauer | Tests | Meldungen |
|---|---:|---|---|
| `address` (`swift test --sanitize=address`, ohne Globals) | 110 s | 402 Tests in 56 Suiten bestanden, 3 übersprungen | ASan 0, UBSan 0 |
| `thread` (`swift test --sanitize=thread`) | 159 s | 402 Tests in 56 Suiten bestanden, 3 übersprungen | TSan 0 |

Übersprungen: zwei nur von Hand gedachte Tests (echter Secure Enclave, Fixture-Erzeugung) und unter Sanitizern der
Exit-Test zur Seed-Länge (siehe 2.2). Dauer mit Neubau der Sanitizer-Ziele; ein früherer Lauf mit demselben Code
brauchte 63 s bzw. 101 s. Protokolle: `build/sanitizer/address.txt`, `build/sanitizer/thread.txt`.

### 2.2 Funde und Behebungen (Testumgebung)

Der erste ASan-Lauf (vor den Änderungen) endete mit 4 gescheiterten Tests (12 Meldungen), alle in der Testumgebung,
keiner im Produktcode:

1. **Laufzeitgrenzen** (`laufzeit64Zeichen`, `laufzeitMitNeuenMustern`, `sehrLangeEingabeBleibtSchnellUndEndlich`):
   unter ASan fünf Proben über 0.15 s, 0.70–1.42 s statt < 0.25 s bzw. 12.5 s statt < 2 s.
   → `Tests/SiegelCoreTests/SanitizerHilfe.swift`:
   Grenzen × `SIEGEL_ZEITFAKTOR` (sanitizer.sh setzt 12 für ASan, 30 für TSan; ohne Sanitizer 1, also unverändert).
2. **Exit-Test** „Seed-Länge ≠ 64 …“ (Befund #20): Der Kindprozess startet unter ASan nicht („Interceptors are not
   working. This may be because AddressSanitizer is loaded too late“). → unter einem Sanitizer abgeschaltet
   (Erkennung über `dlsym("__asan_init"/"__tsan_init")`); im normalen `swift test` läuft und besteht er.
3. `sanitizer.sh` meldete nur das letzte Testziel (308 statt 402 Tests) und zählte die Gesamtzeile als gescheiterten
   Test mit. → zählt jetzt alle Testziele, die übersprungenen und nur echte Fehlschläge.

Danach beide Läufe grün, ohne eine einzige Sanitizer-Meldung.

## 3. Python-Gegenprobe

- `referenz/gegenprobe.sh`: **alles stimmt** (119 Prüfpunkte): beide Beispieldateien öffnen mit Passwort (und bei v2
  den drei Faktoren), Kopfwerte, SHA-256, alle Einträge samt TOTP und Verlauf wie erwartet; je 9 gekippte Bytes mit und
  ohne neu berechnete Prüfsumme abgelehnt; gekürzt, verlängert und falsches Passwort abgelehnt.
- `referenz/differenz.sh` (neu): Der Fuzzer schreibt Mutanten der Beispieldateien samt Swift-Urteil
  (`SiegelFuzz --mutanten`), die Python-Referenz liest jeden selbst (Struktur, dann Passwortweg mit den Werten aus
  `Fixtures/README.md`). 300 Mutanten (Saat 7) und 2000 Mutanten (Saat 20261017), beide: **keine Abweichung**.

| 2000 Mutanten | Anzahl |
|---|---:|
| beide lehnen ab (Struktur) | 1526 |
| beide lesen die Struktur | 380 |
| davon Python voll geöffnet: abgelehnt `corruptFile.payload` / `wrongPassword` / `wrongCard` | 157 / 148 / 26 |
| davon unverändert (geöffnet, erwartet) | 71 |
| gewollter Unterschied: Python prüft den KDF-Bereich schon im Kopf | 62 |
| gewollter Unterschied: Swift strenger (`payload.length` 29, `header.fidoSalt` 2, `header.seKeyID` 1) | 32 |
| anderes KDF-Profil, in Python nicht voll gerechnet | 10 |

Kein Mutant öffnete in Python oder Swift; jede Struktur-Abweichung gehört zu den dokumentierten, gewollten
Unterschieden (Swift verlangt zusätzlich ctLen − 16 als Vielfaches des Polsters und nicht leere seKeyID/fidoSalt bei
gesetztem Bit; Python prüft den KDF-Bereich vor dem Ableiten statt beim Lesen).

## 4. Abschluss

- `swift test`: 402 Tests grün (SiegelCoreTests 308 in 44 Suiten, SiegelHardwareTests 94 in 12 Suiten), 0 Warnungen;
  übersprungen nur die zwei Handtests.
- `swift build -c release --product SiegelFuzz`: baut ohne Warnung; das Programm meldet nur „läuft nur im Debug-Bau“.
- `./build.sh`: Grep-Sperren ok (124 Dateien; SiegelFuzz ist wie SiegelSnapshots und Tests ausgenommen), Release
  0 Warnungen, ad-hoc-Signatur, 6 Entitlements, Bündelinhalt, Installation nach `~/Applications/Siegel.app` ok. Vorher
  lief keine Siegel-Instanz.
- Kein Tresor im App-Container angelegt, keine Touch-ID-, Kamera- oder Sicherheitsschlüssel-Dialoge: Faktoren sind im
  Fuzzer feste Testwerte, Saat-Tresore entstehen nur im Temp-Ordner mit dem Testschalter-KDF.

## 5. Reproduktion

```bash
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
skripte/fuzz.sh 30 --saat 17102026          # Lauf 2 wiederholen (alle Ziele parallel, je 30 min)
skripte/fuzz.sh 20 --nacheinander           # 20 min insgesamt, nach Gewicht verteilt
skripte/fuzz.sh --wiederholen build/fuzz/funde/<datei>.bin <ziel>
skripte/sanitizer.sh                        # ASan + TSan über swift test
referenz/gegenprobe.sh
referenz/differenz.sh 2000 20261017
```

## 6. Neue und geänderte Dateien

- Neu: `Sources/SiegelFuzz/` (main, Haupt, Lauf, Grundlagen, Saat, Ziel*.swift, FUZZ-NOTIZEN.md),
  `Sources/SiegelFuzzAbdeckung/` (SanitizerCoverage-Rückrufe), `skripte/fuzz.sh`, `referenz/differenz.sh`,
  `Tests/SiegelCoreTests/SanitizerHilfe.swift`, dieser Bericht.
- Geändert: `Package.swift` (Ziele SiegelFuzz, SiegelFuzzAbdeckung), `skripte/sanitizer.sh` (Zeitfaktor,
  Zusammenfassung über alle Testziele), drei Laufzeit-Tests (`PasswordStrengthTests`, `VorlagenTests`) und der
  Exit-Test (`KernRundlaufTests`), `SPEC.md` (v4.2 in §12, Hinweis in §21), `LIESMICH.md`, `referenz/README.md`.

## 7. Runde 2 – Abschluss nach der zweiten Prüfung (17.10.2026)

Nach Runde 1 hat eine zweite Prüfung den Stand in sieben Dimensionen durchgesehen; die Befunde sind behoben und in
`SPEC.md` §12 (v4.4) festgehalten, die Handprüfungen dazu in `PRUEFLISTE.md` §18–§20. Danach lief der ganze
Abschluss neu (10:10–10:37 Uhr), auf demselben Gerät und mit derselben Werkzeugkette wie oben.

### 7.1 Befunde je Dimension

„Eigenständig“ zählt ohne Befunde, die laut SPEC derselbe Fehler wie ein anderer sind (dort nur ergänzt).

| Dimension | Befunde | eigenständig | Was sich geändert hat (kurz) | Belege |
|---|---:|---:|---|---|
| Krypto | 3 (krypto-1 bis -3) | 3 | Vernichtungs-Passwort an die Faktoren der Stufe gebunden (kein zweites Master-Passwort ohne Faktoren mehr); Vernichtungs-Sitzung mit echtem DEK, danach DEK-Erneuerung beim nächsten echten Entsperren; `reuseTag` über `OpaqueString` | 3 Suiten „Krypto-Befunde: …“ |
| Datei | 5 (datei-1 bis -5) | 5 | kein Schreiben nach `lock()` (`io("vault.locked")`); Notfallweg ohne Tresordatei und für eine gewählte Sicherung; ungeprüfter Kopf nur für die Wahl Code/Teile; Zähler-Warnung auf allen Sicherungswegen | 3 Suiten „Datei-Befunde: …“, Snapshots 170–182 |
| Hardware | 4 (hardware-1 bis -4) | 4 | `factorTemporarilyUnavailable` (Touch ID gesperrt bzw. nicht erreichbar, ohne Notfallweg); Signatur-Selbstprüfung als Erstes; `wrongSecurityKey`; Abbrechen beim Sicherheitsschlüssel mit CTAPHID_CANCEL | Suiten Secure Enclave, Sicherheitsschlüssel, Signatur-Selbstprüfung; Snapshots 38b, 98c, 98d, 111b, 113c |
| Hygiene | 5 (hygiene-1 bis -5) | 5 | Sperren mit geschützter Bearbeitung nur versiegelt (keine stille Klartext-Kopie mehr); Zwischenablage beim App-Wechsel; ⌘C-Dauer nach Eintrags-Schutz; Kamera-Vorschau hinter der Verdeckung; keine Totmann-Frist nach einer Vernichtung | Snapshots 151, 190–193 |
| Abläufe | 10 (ablaeufe-1 bis -10) | 5 | 1, 2, 6, 8, 9 = hygiene-1, hygiene-2, datei-5, hygiene-3, hardware-1 (nur ergänzt). Neu: Sperrbildschirm nach einer Vernichtungs-Sitzung, keine Faktor-Abfragen nach dem Sperren (auch im Kern), markierte Einträge ohne Auslöser, „Jetzt einrichten…“ aus der Bearbeitung, Sicherungen im Hintergrund lesen | Snapshots 107/108/112, 230–233 |
| Bau | 4 (bau-1 bis -4) | 4 | Autofill-Erweiterung: vorübergehendes Touch ID nicht endgültig, eingefügtes Master-Passwort wird geleert, Meldung nach gescheiterter Auswahl bleibt sichtbar; Erweiterung als Paketziel testbar; Grep-Sperren: `NSLogv`, Regex-Literale mit Rückfallnetz | neues Testziel `SiegelAutofillTests` (13 Tests), Grep-Selbsttest |
| Design | 7 (design-1 bis -7) | 6 | design-1 = ablaeufe-7. Neu: Sperrbildschirm im kleinsten Fenster, Text „Sicherung exportieren“ nach Stufe, Karte abtippen, Kurztexte der Schutz-Auswahl, „Kein CSV- und KeePass-Export“, „die Secure Enclave“ | Snapshots 157b (Rahmen gemessen bei 920×600 und 760×480), 68b, 81, 86c, 99 |
| **Summe** | **38** | **32** | | |

Bewusst nicht umgesetzt (in SPEC v4.4 begründet): Touch-ID-Dialog beim Sperren per `LAContext.invalidate()` schliessen
(ohne Dialog nicht prüfbar), Knopf „Mit Mac-Passwort freigeben“, gemeinsames AppKit-Modul für App und Erweiterung,
Sperre beim App-Wechsel bis zum Ablauf der Zwischenablage aufschieben. Ehrliche Grenze aus krypto-3: alte Tags
versiegelter Einträge erkennt der Kern nicht, wenn das Master-Passwort mit U+0020 statt U+00A0 getippt wird.

### 7.2 Läufe nach den Fixern

| Prüfung | Umfang | Ergebnis |
|---|---|---|
| `swift test` | 487 Tests in 69 Suiten: SiegelCoreTests 360 (55 Suiten), SiegelHardwareTests 114 (13), SiegelAutofillTests 13 (1); 38 s | **grün**, übersprungen nur die zwei Handtests |
| Harte Regeln (SPEC §5) | Grep-Sperren über 133 Dateien; zusätzlich Suche nach `try!`, `as!` und `!`-Unwrap in SiegelCore/SiegelUI/SiegelHardware | 0 Verstösse; die Suche fand weder `!`-Unwrap noch erzwungenen Cast im Code (Treffer nur in Wortlisten-Literalen) |
| `referenz/gegenprobe.sh` | v1 + v2 Beispieldatei, 119 Prüfpunkte, 5.6 s | **alles stimmt** |
| `skripte/fuzz.sh 10` | 11 Ziele parallel je 10 min, ASan + Kanten-Abdeckung, 27.6 Mio. Eingaben (§7.3) | **0 Funde**, kein Absturz, kein Hänger, alle Exit 0 |
| `skripte/sanitizer.sh address` | `swift test --sanitize=address`, 487 Tests, 74 s | bestanden, ASan 0, UBSan 0 |
| `skripte/sanitizer.sh thread` | `swift test --sanitize=thread`, 487 Tests, 116 s | bestanden, TSan 0 |
| Snapshots (Release) | `SiegelSnapshots`, 204 Bilder mit allen Ablauf-Prüfungen, 10:24 min | **bestanden**; alle 204 Bilder auf 34 Kontaktbögen angesehen (§7.4) |
| `./build.sh` | Grep-Sperren, Release, ad-hoc-Signatur, 6 Entitlements, Bündelinhalt, Installation | grün, 0 Warnungen; zur Kontrolle ein Release-Bau in leerem Bauordner: 0 Warnungen (43 s). Vorher lief keine Siegel-Instanz |
| App starten/beenden | `~/Applications/Siegel.app` geöffnet, `skripte/fenster_pruefen.swift`, Beenden per Apple Event „quit“ | 1 Fenster, `sharingState 0`; nach 28 s sauber beendet, kein Absturzbericht; App-Container unverändert (nur `.lock`, kein Tresor angelegt) |

Gegenüber Runde 1: 85 Tests mehr (Kern +52, Hardware +20, Autofill neu 13), 21 % mehr instrumentierte Kanten im
Fuzzer (117 046 statt 96 071). Behoben werden musste in diesem Abschluss nichts – weder im Produktcode noch in den
Prüfwerkzeugen.

### 7.3 Fuzz-Rauchtest

Saat `1792225187`, 11 Ziele parallel, ASan + Kanten-Abdeckung, 10:19–10:29 (Binärdatei `018aa323…`). Saat-Korpus
unverändert aus `build/fuzz/saat/` (gleiche SHA-256 wie in §1.2); der Selbsttest öffnet ihn auch mit v4.4.
Ergebnis in `build/fuzz/lauf-20261017-101953/`.

| Ziel | Minuten | Eingaben | pro s | Ergebnisarten | Kanten (neu im Lauf) | Funde | Exit | langsamste Eingabe (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `datei` | 10.0 | 331'366 | 552 | 34 | 4962 (+845) | 0 | 0 | 0.75 |
| `inhalt` | 10.0 | 144'008 | 240 | 13 | 9226 (+1517) | 0 | 0 | 0.61 |
| `notfall` | 10.0 | 12'159 | 20 | 17 | 2652 (+1330) | 0 | 0 | 2.37 |
| `karte` | 10.0 | 1'898'698 | 3'164 | 3 | 1048 (+618) | 0 | 0 | 0.12 |
| `csv` | 10.0 | 28'454 | 47 | 17 | 1784 (+1528) | 0 | 0 | 0.92 |
| `totp` | 10.0 | 1'333'101 | 2'222 | 16 | 1271 (+1015) | 0 | 0 | 0.13 |
| `cbor` | 10.0 | 2'940'621 | 4'901 | 81 | 1386 (+878) | 0 | 0 | 0.08 |
| `ctaphid` | 10.0 | 18'904 | 32 | 91 | 2330 (+770) | 0 | 0 | 0.81 |
| `hwdatei` | 10.0 | 9'930'685 | 16'551 | 9 | 799 (+375) | 0 | 0 | 0.10 |
| `sicherung` | 10.0 | 5'937'501 | 9'896 | 6 | 1103 (+666) | 0 | 0 | 0.10 |
| `autofill` | 10.0 | 5'017'219 | 8'362 | 4 | 734 (+479) | 0 | 0 | 0.13 |
| **Summe** | **1.83 h** | **27'592'716** | | | | **0** | | |

`datei` und `inhalt` erreichen mehr Kanten als im 30-min-Lauf 2 von Runde 1 (4962 statt 4774, 9226 statt 8825: neuer
Kern-Code), `ctaphid` prüft die neuen Fehler `wrongSecurityKey` und `factorTemporarilyUnavailable(.securityKey,
"fido.busy")` mit. Mit allen Läufen von Runde 1 zusammen: 11.9 Fuzz-Stunden, 163.8 Mio. Eingaben, 0 Funde im
Produktcode.

### 7.4 Kontaktbogen

`swift skripte/kontaktbogen.swift` (neu, ohne Fremdbibliothek) legt die Snapshots zu je 6 auf Kontaktbögen
(`build/kontaktbogen/kontaktbogen-01.png` bis `-34.png`). Alle 204 Bilder angesehen: Jedes ist vollständig gerendert,
nichts ungewollt abgeschnitten, keine Überlappung, kein leeres Bild, Texte Deutsch (Schweiz, ss, per du).
Gezielt vergrössert: 38 (Anführungszeichen „./build.sh run“), 99 (Schutz 5 mit „noch einrichten“ und drei Symbolen
passt in die Zeile, design-5), 157b (Frist als eigene Zeile, keine Überlappung mit der Zähler-Warnung, design-2).
58 Bilder haben absichtlich ein anderes Format: höher bis zur vollen Länge (z. B. 14, 92 und 125 „ganz“, bis
920×2180 pt), das kleinste Fenster (57, 157b: 760×480) oder ein Blatt (40, 40b, 117, 118); sie erscheinen auf dem
Bogen verkleinert und wurden wo nötig einzeln angesehen.

### 7.5 Grenzen (ehrlich)

- Der Rauchtest ist kurz (10 min je Ziel); der Langlauf aus Runde 1 lief mit dem Stand v4.2. Die v4.4-Änderungen an
  `persist`, Vernichtungs-Passwort und Sicherungswegen sind über Unit-Tests und den Rauchtest abgedeckt, nicht über
  Stunden.
- Der Fuzzer kennt keine Saat mit Selbstvernichtung (Vernichtungs-Passwort, `duressEnvelope`, vernichtbare Einträge)
  und benutzt das Abbruch-Token `SecurityKeyCancellation` nicht. Nächster Schritt: eine Saat mit eingerichteter
  Selbstvernichtung, ein Abbruch-Zeitpunkt im Ziel `ctaphid`, dann `skripte/fuzz.sh 30 --neue-saat`.
- Den Inhalt des laufenden App-Fensters zeigt kein Screenshot (`sharingState 0`, gewollt); geprüft sind Start, Fenster
  und Beenden. Die Handprüfungen `PRUEFLISTE.md` §18–§20 (mit Testtresor, Touch ID, Kamera) stehen noch aus.
- In `~/Library/Logs/DiagnosticReports/` liegen vier Absturzberichte `SiegelProbe-2026-10-17-0627*.ips`
  (EXC_BREAKPOINT) von einem Probeprogramm der Fixer aus einem Temp-Ordner, nicht von der App; nicht gelöscht.

### 7.6 Reproduktion Runde 2

```bash
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
swift test
referenz/gegenprobe.sh
skripte/fuzz.sh 10 --saat 1792225187
skripte/sanitizer.sh
swift build -c release --product SiegelSnapshots && .build/release/SiegelSnapshots snapshots
swift skripte/kontaktbogen.swift            # build/kontaktbogen/
./build.sh
```

Geändert in diesem Abschluss: `PRUEFBERICHT.md` (dieser Abschnitt), `LIESMICH.md` (Zahl der Bildschirme 204,
SPEC-Version v4.4, Kontaktbogen), neu `skripte/kontaktbogen.swift`; `snapshots/` neu gerendert.

## 8. Runde 3 (Selbstvernichtung im Fuzzer), 17.10.2026 nachmittags und abends

Anlass: §7.5 nannte als Lücke, dass der Fuzzer keine Saat mit Selbstvernichtung kennt und das Abbruch-Token des
Sicherheitsschlüssels nicht benutzt. Die Runde hatte vier Schritte: Aufbau von Saaten, Ziel und Invarianten (dabei
fand der Fuzzer acht Fehler im Produktcode, §8.2), Wirksamkeitsproben (§8.3), Langlauf mit dem endgültigen Stand
(§8.4) und Abschluss (§8.5). Weil Produktcode geändert wurde, steht die Änderung als v4.5 in `SPEC.md` §12.
Einzelheiten zu Rahmung, Orakel und Vorgängen: `Sources/SiegelFuzz/FUZZ-NOTIZEN.md`.

### 8.1 Neue Saaten, Ziele und Invarianten

**Vernichtungs-Saaten.** Gebaut über die `@testable`-Schnittstelle mit DEBUG-KDF-Testschalter, fester Uhr
(`TestHooks.now` = 1 792 000 000) und Test-Faktoren (Software-P256 statt Secure Enclave, Schlüssel roh in
`Hardware/<keyID>.siegelhw`, feste q und y; keine Biometrie, keine Dialoge), im Temp-Ordner, nie im App-Container.
Zu jeder Saat liegt der ganze Tresorordner unter `build/fuzz/saat/<name>.umgebung/` (Tresordatei, Sicherungen,
`Hardware/` mit `zustand.json`, Ablage des Vernichtungs-Passworts, V, Eintrags-SE-Schlüssel und einem Platzhalter für
den Entsperr-SE-Schlüssel). Jede Saat hat eigene Kennungen und eigenes Material für V und den Eintrags-Schlüssel,
`v5` ein eigenes Master-Passwort – so entsteht beim Vertauschen „fremdes Material unter dem richtigen Namen“.

| Saat | Stufe | Einstellungen | Einträge | Zustand |
|---|---|---|---|---|
| `v4` | 4 | Totmann 30, Zähler 20, Vernichtungs-Passwort | vernichtbar Schutz 4 ×2, nicht vernichtbar Schutz 4, dazu Schutz 1–3 | eingerichtet |
| `v5` | 5 | Totmann 7, Vernichtungs-Passwort | vernichtbar Schutz 5 und 4, nicht vernichtbar Schutz 5 | eingerichtet |
| `v4z` | 4 | Zähler 10 | vernichtbar / nicht vernichtbar Schutz 4 | 9 Fehlversuche, kurz vor der Schwelle |
| `v4t` | 4 | Totmann 7, Vernichtungs-Passwort | vernichtbar / nicht vernichtbar Schutz 4 | über den Totmann vernichtet |
| `v5x` | 5 | Totmann 365, Zähler 50, Vernichtungs-Passwort | vernichtbar Schutz 5 und 4, nicht vernichtbar | über das Vernichtungs-Passwort vernichtet, `rekeyPending` |

Beim Vorbereiten von `vernichtung` und `sicherung` öffnet der Fuzzer jede Sicherung im Tresorordner einer
Vernichtungs-Saat mit dem Notfallcode und prüft §23.1 (kein vernichtbarer Eintrag lesbar).

**Neues Ziel `vernichtung` (§23).** Jede Eingabe baut den Tresorordner einer Saat A im Temp-Ordner nach und verändert:

- `zustand.json` strukturbewusst (Felder, Typen, Zeiten an der Frist ± 1 s, ±∞/NaN/-0/1e999, Zähler an der Schwelle,
  Kennungen aller Saaten samt Entsperr- und Eintrags-SE-Schlüssel, vaultID, `rekeyPending`) oder bytenah; als Datei,
  fehlend, Ordner oder Symlink;
- die Ablage des Vernichtungs-Passworts (Bitfehler je Bereich, Art, keyID, Version, Länge, Punkt; Prüfsumme meist neu
  berechnet), dazu Zustand und Ablage einer zweiten Saat B;
- die Welt: V fehlt, V von B dazu, V-Material von B unter dem Namen von A, Tresordatei kaputt oder weg,
  Rollback-Wächter, schreibgeschützter Hardware-Ordner (`chflags uchg`), Vernichtungs-Schicht, die wirft oder still
  nichts tut, und ein Wettlauf zwischen Probe und Vermerk (DEBUG-Haken `TestHooks.afterDuressArgon`).

Danach folgen bis zu 12 von 15 Vorgängen: Status, Totmann mit gefuzzter Uhr, Entsperren mit falschem, eigenem,
früherem und fremdem Vernichtungs-Passwort und dem echten Passwort (je mit Faktor-Varianten), Sicherung einspielen,
Speichern, Passwortwechsel, Selbstvernichtung einstellen und markieren (mit `purgeBackups`), Notfallweg, Verbotenes in
der Vernichtungs-Sitzung, alte Ablage zurücklegen. **Orakel:** ein eigenes Modell der Abläufe aus `KERN-NOTIZEN.md`
(Totmann, Zähler, Vernichtungs-Passwort mit DEK-Epochen, Rotation, Speichern, Notfallweg, Schreibschutz) mit eigenem
Leser für `zustand.json` und Ablage und eigener Prüfwert-Rechnung (libsodium Argon2id, CryptoKit HKDF). Ob der Kern
`zustand.json` annimmt, entscheidet sein eigener Parser; der eigene Leser muss Feld für Feld dasselbe ergeben. Je
Vorgang verglichen: Ergebnis, Folge der Aufrufe der Vernichtungs-Schicht, Inhalt des Hardware-Ordners (auch welche
Dateien überschrieben wurden), `zustand.json` Feld für Feld, Tresordatei, und in Sitzungen Art, sichtbare Einträge,
jedes Aufdecken gegen die Soll-Geheimteile, V-Freigaben und Status. Jeder Widerspruch ist ein Fund.

Modellfreie Invarianten (zusätzlich zum Modell):

1. Kein Absturz, kein Hänger; Fehler je Vorgang nur aus festen Mengen; das echte Passwort mit richtigen Faktoren und
   intakter Datei öffnet immer eine echte Sitzung, auch ganz am Schluss.
2. Der Entsperr-SE-Schlüssel wird nie gelöscht oder verändert; gelöscht wird nur, was ein Zustand nennt.
3. Eine Vernichtungs-Sitzung gibt es nur mit dem eigenen Vernichtungs-Passwort und einer erkennenden Ablage;
   Tresordatei und Sicherungen bleiben dabei bytegleich (ebenso bei jedem Vorgang ohne Erfolg). Keine Abfrage verrät
   die vernichtbaren Einträge (Differenz gegen den ungefilterten Inhalt: Liste, Bericht, Wiederverwendung,
   `lastModified`, Status).
4. Nicht vernichtbare Einträge bleiben lesbar, solange der Eintrags-SE-Schlüssel da ist; vernichtbare nur mit dem
   eigenen, unveränderten V.
5. Vermerk ⇒ V weg (mit Gegenprobe über den Datei-Anbieter: `factorUnavailable(.secureEnclave)`).
6. Rotation entwertet alte Umschläge: Nach jedem neuen Zugang öffnet kein früherer Umschlag die neue Tresordatei, das
   Salz ist neu, die eben geschriebene Ablage öffnet sie.
7. Nach dem Markieren liefert keine Sicherung mit dem Notfallcode einen vernichtbaren Eintrag.

Bewusst **kein** Fund: Ein manipulierter `zustand.json` darf im gesperrten Zustand auslösen (abgelaufene Frist, Zähler
an der Schwelle, Vermerk) und löscht dann, was er als V nennt – gesperrt gibt es keinen Schlüssel, der ihn prüfen
könnte, und wer dort schreiben kann, kann jede Datei auch direkt löschen (KERN-NOTIZEN.md, SICHERHEIT.md). Ein
vertauschter Zustand (fremde vaultID) und eine fremde Ablage lösen nie aus.

**Erweiterte Ziele.**

- `ctaphid`, Art 4–7: Abbruch über `SecurityKeyCancellation` beim n-ten Ereignis (vor dem Start, KEEPALIVE,
  Antwortpaket, Senden, Stille, Empfang), aus einem zweiten Thread (Art 6) bzw. während das Gerät 1,5 s schweigend auf
  Berührung wartet (Art 7). Invarianten: vor dem Start kein einziges Paket; sonst `factorCancelled`, Erfolg nur ohne
  offene Anfrage und dann mit genau dem HMAC; danach keine neue CBOR-Anfrage; war eine offen, folgt CTAPHID_CANCEL;
  Ende innert 1 s (×4 unter ASan), bei Art 7 innert 0,25 s (×2); ein zweiter ungestörter Ablauf liefert genau das HMAC.
- `sicherung`, Art 3 „Einspielen“ (alle Testschalter-Saaten, mit Vernichtungs-Saaten auch
  `restoreNewestReadableBackup`): eingesetzt wird nur die unveränderte Datei mit dem echten Passwort, nie als
  Vernichtungs-Sitzung; danach Zähler 0, Einstellungen aus dem Inhalt, Einträge wie erwartet; ohne Erfolg alles
  bytegleich; nur `wrongPassword` zählt, an der Schwelle wird V vernichtet.
- `inhalt`: V nach Kennung (vernichtete Einträge genau `factorUnavailable(.secureEnclave)`); Vernichtungs-Saaten
  zusätzlich durch `store.unlock` (keine Schlüssel-Datei wird überschrieben), gezielte Mutation der Kennungen.
  `datei` und `notfall` nehmen die neuen Saaten automatisch mit.
- `skripte/fuzz.sh`: `vernichtung` in allen Läufen; Gewichte für `--nacheinander` neu verteilt (vorher in Wahrheit
  Summe 106, jetzt genau 100; `vernichtung` 14).

### 8.2 Funde und Fixes

Alle acht Funde liegen im Kern (SiegelCore), alle sind behoben und haben einen Regressionstest in der Suite
„Fuzz-Befunde: Selbstvernichtung“ (`Tests/SiegelCoreTests/Kern/KernVernichtungFuzzBefundeTests.swift`, 9 Tests).
Für vernichtung-4 bis -8 ist belegt, dass der Test ohne den Fix scheitert (Fix vorübergehend entfernt, danach bytegleich
zurückgesetzt).

| Befund | Ziel | Ursache | Fix | Regressionstest |
|---|---|---|---|---|
| vernichtung-1 | `vernichtung` | `zustand.json` nannte den Entsperr-SE-Schlüssel als V bzw. vernichtet: Zähler-Schwelle oder Totmann löschten ihn → Tresor nur noch mit Notfallcode | Ein solcher Zustand gilt nicht (`currentState`, `DestructionState.names`) | `entsperrSchluesselNieVernichten` |
| vernichtung-2 | `vernichtung` | `duressFileID` = V bzw. Eintrags-SE-Schlüssel: echtes Entsperren und Speichern löschten ihn als „veraltete Ablage“ | `removeStaleDuressFile` löscht nie einen Schlüssel in Gebrauch | `alteAblageNieInGebrauch` |
| vernichtung-3 | `vernichtung` | `checkDeadman(now: +∞)` löschte V, der Vermerk war nicht schreibbar | Unbrauchbare Uhr (±∞, NaN) wie rückwärts: nichts | `uhrUnbrauchbar` |
| vernichtung-4 | `vernichtung` | Wettlauf: Der Vermerk nach dem Vernichtungs-Passwort las `zustand.json` ungefiltert; ein zwischen Probe und Vermerk getauschter Zustand liess den Kern den Entsperr-SE-Schlüssel löschen | Vermerk liest über `currentState`; gilt der Zustand nicht, wird nichts vermerkt und nichts gelöscht | `wettlaufProbeUndVermerk` |
| vernichtung-5 | `vernichtung` | Schreibgeschützter Hardware-Ordner: `io("file.create")` statt des dokumentierten `io("destruction.write")` | Jeder Schreibfehler an Zustand bzw. Ablage → `io("destruction.write")` | `hardwareOrdnerNichtBeschreibbar` |
| vernichtung-6 | `vernichtung` | Tresordatei fehlt: der Zustand galt ungefiltert und konnte den Entsperr-SE-Schlüssel der Sicherung löschen, die man dann einsetzt | Ohne lesbaren Kopf gilt kein Zustand, der den Entsperr-SE-Schlüssel einer eigenen Sicherung nennt (`backupUnlockKeyIDs`) | `ohneTresordateiNieAussperren` |
| vernichtung-7 | `vernichtung` | Notfallweg (neuer Kopf ohne Faktoren) entfernte als „veraltete Ablage“ auch den alten Entsperr-SE-Schlüssel, den Eintrags-Schlüssel oder V, die ältere Sicherungen noch brauchen | Gelöscht wird nur eine Datei, die wirklich eine Ablage mit dieser Kennung ist (`readDuressFile`) | `notfallwegLoeschtNurAblagen` |
| vernichtung-8 | `inhalt` | Inhalt mit Ablage-Kennung = Name der V-Datei (nur über einen fehlerhaften Schreiber erreichbar): Kapseln überschrieb die V-Datei per rename | `writeDuressFile` ersetzt nur eine Datei in Ablage-Form, sonst `io("destruction.write")` | `ablageUeberschreibtKeinenSchluessel` |
| Tiefenverteidigung | – | `checkDestruction` liess gleiche Kennungen für V, Ablage und SE-Schlüssel zu | Paarweise verschieden und nie der Entsperr-SE-Schlüssel (`checkDestruction`, `destructionKeysAvoid` in `decryptPayload` und `persist`) | `schluesselKennungenVerschieden` |

Geänderter Produktcode (Endstand, SHA-256): `DestructionState.swift` `a8c5c8fa…`, `VaultStore+Vernichtung.swift`
`0533e110…`, `VaultStore+Zugang.swift` `76c001fe…`, `VaultStore.swift` `f4254723…`, `VaultCrypto.swift` `cd85446f…`,
`VaultContent+Schutz.swift` `b8f28484…`, `TestHooks.swift` `a5eaeca1…` (nur DEBUG). `SiegelHardware/FIDO2/CTAPHID.swift`
ist unverändert (`bcea944d…`): Die Abbruch-Invarianten in `ctaphid` fanden nichts.

Ausserhalb des Produktcodes:

- `skripte/fuzz.sh` endete trotz Fund immer mit Exit 0, weil der Wert in der Subshell der Pipe verloren ging. Behoben:
  Exit 1 bei Fund, Absturz oder Hänger.
- Testumgebung (im Abschluss, §8.5): Der Test „Zufälliger Code → kein Treffer“ (`KernNotfallcodeTests.swift`) hatte
  als einzige Laufzeitschranke über instrumentiertem Swift-Code eine feste Grenze (60 s) ohne `Sanitizer.zeitfaktor`.
  Unter TSan und Fremdlast dauerte die volle Fehlerkorrektur-Suche länger. → Grenze × `SIEGEL_ZEITFAKTOR` wie die
  übrigen Laufzeittests (§2.2); ohne Sanitizer unverändert 60 s. Die Schranke in `KernZugangTests` (abgelehnte
  KDF-Parameter < 30 s) bleibt fest: Sie misst, dass Argon2 gar nicht erst läuft, und libsodium ist nicht instrumentiert.
- Gerüst: Die Fund-Dateien der Aufbauphase liegen in `build/fuzz/funde/erledigt-20261017/` (1299 `ctaphid`,
  8 `vernichtung`, 1 `inhalt`; Produktfunde und Fehlalarme beim Nachschärfen von Modell und Gerätenachbildung). Die
  `ctaphid`-Meldungen („Antwort trotz schweigendem Gerät“, 1298-mal in Art 7 zwischen 19:27 und 19:35) waren ein
  Fehler der Gerätenachbildung im Fuzzer; `CTAPHID.swift` blieb dafür unverändert. Bei einer Probe mit `--neue-saat`
  scheiterte die Saat-Prüfung zuerst an einer Sicherung mit älterem Notfallkit (`wrongRecoveryCode`); solche
  Sicherungen überspringt die Prüfung jetzt.

### 8.3 Wirksamkeitsproben

Fehler vorübergehend in Kern bzw. Hardware-Schicht eingebaut, Fuzzer unter ASan gefahren, danach zurückgesetzt und per
SHA-256 verglichen (alle Rücknahmen bytegleich; nach den Langlauf-Proben ist auch die neu gebaute Binärdatei wieder
genau `e5d9a8ea…`). „Selbsttest“ heisst: Schon die Vorbereitung des Ziels scheitert, vor der ersten gefuzzten Eingabe
(Wanduhr inkl. Start 4–7 s). Die Fund-Dateien liegen in `build/fuzz/funde/proben-20261017/` und
`…/proben-20261017-langlauf/`; mit dem zurückgesetzten Code laufen sie per `--wiederholen` ohne Fund durch.

Beim Aufbau (Saat 4242):

| Probe | Eingebauter Fehler | Ziel | Ergebnis | Meldung |
|---|---|---|---|---|
| p1 | Zähler zählt beim Entsperren einen Versuch, der nicht zählen darf | `vernichtung` | gefunden, Selbsttest (7 s) | Vorgang 2: `zustand.json` „fehl 1 statt unverändert“ |
| p1k | derselbe Fehler beim Einspielen (Kontrolle) | `sicherung` | gefunden nach 1,7 s / 347 Eingaben | „Zustand verändert ohne Fehlversuch (corruptFile)“ |
| p2 | letzte echte Entsperrung falsch nachgeführt (Uhr zurückgestellt) | `vernichtung` | gefunden, Selbsttest (6 s) | Vorgang 4: „letzte 1792003600 statt 1794592001“ |
| p3 | Vernichtungs-Sitzung schreibt Tresordatei bzw. Sicherungen | `vernichtung` | gefunden, Selbsttest (4 s) | „Vernichtungs-Sitzung verändert Tresordatei oder Sicherungen“ |
| p4 | Markieren bereinigt die Sicherungen nicht | `vernichtung` / `sicherung` | gefunden, Selbsttest (5 s); mit `--neue-saat` in der Saat-Prüfung von `sicherung` (7 s) | „nach dem Markieren liefert eine Sicherung … vernichtbaren Eintrag (§23.1)“ |
| p5 | `destructionStatus` liefert einen falschen Stand | `vernichtung` | gefunden nach 1 s / 11 Eingaben | „destructionStatus … statt …“ |
| p6 | kein Rückfall des Kerns, wenn die Vernichtungs-Schicht V nicht löscht | `vernichtung` | gefunden, Selbsttest (4 s) | „vermerkter Schlüssel liegt noch da“ |
| p7 | Passwortwechsel kapselt die Ablage nicht neu | `vernichtung` | gefunden, Selbsttest (4 s) | Vorgang 10: Ablage nicht neu geschrieben |
| p8 | Abbruch ohne CTAPHID_CANCEL | `ctaphid` | gefunden nach 0 s / 6 Eingaben | „Anfrage offen beim Abbruch, aber kein CTAPHID_CANCEL“ |
| x1 | Vernichtungs-Sitzung zeigt den Vermerk der Vernichtung | `vernichtung` | gefunden, Selbsttest | „Vernichtungs-Sitzung zeigt den Vermerk der Vernichtung“ |
| x3 | V bleibt auf einem weiteren Weg nach dem Vermerk liegen | `vernichtung` | gefunden nach 4,1 s / 40 Eingaben | „vermerkter Schlüssel liegt noch da“ |
| x4 | Abbruch wird erst nach dem Zeitlimit des Empfangs wirksam | `ctaphid` | gefunden nach 1,5 s / 6 Eingaben | „Abbruch aus dem zweiten Thread erst nach 1.51 s wirksam“ |
| x5 | erste Schicht gegen „Ablage-Kennung = Schlüssel-Datei“ entfernt (`checkDestruction`) | `inhalt` | **nicht gefunden** in 600 s / 193 049 Eingaben | – |
| x5 + x6 | dazu die Form-Prüfung in `writeDuressFile` entfernt | `inhalt` | gefunden nach 0,6 s / 244 Eingaben | „echtes Entsperren … überschreibt die Schlüssel-Datei“ |

Grund für x5: Die zweite Schicht (Form-Prüfung in `writeDuressFile`, Fix zu vernichtung-8) fängt den Fehler ab, das
Verhalten bleibt korrekt – es gibt nichts zu finden. Ohne beide Schichten findet `inhalt` ihn sofort.

Nach dem Langlauf (endgültiger Stand, `skripte/fuzz.sh 3 --ziele vernichtung --saat 777`, Fehler in
`VaultStore+Vernichtung.swift`):

| Eingebauter Fehler | Ergebnis |
|---|---|
| Totmann erst nach der Frist (`now > Frist` statt `>=`) | gefunden, Selbsttest (Vorgang „Totmann genau an der Frist“: `false` statt `true`), 0 Eingaben |
| kein Rückfall des Kerns, wenn die Vernichtungs-Schicht V nicht löscht | gefunden nach 27 s / 124 Eingaben: „vermerkter Schlüssel liegt noch da“ (Invariante 5) |
| Vermerk des Vernichtungs-Passworts liest `zustand.json` ungefiltert (Rückfall auf vernichtung-4) | gefunden mit der 1. Eingabe (Welt „Wettlauf“): „Vorgang 3 hat den Entsperr-SE-Schlüssel gelöscht oder verändert“ (Invariante 2) |

Summe Runde 3: 17 Proben (16 einzelne Fehler und die Kombination x5 + x6), 16 gefunden (0–27 s), eine aus
nachvollziehbarem Grund nicht (x5 allein).

### 8.4 Langlauf

Binärdatei in allen Läufen `e5d9a8ea36c0e022…` (Debug, ASan ohne Globals, Kanten-Abdeckung; 152 554 instrumentierte
Kanten, Runde 2: 117 046). Saat-Korpus neu erzeugt in Lauf A (`--neue-saat`), danach unverändert:
`t1 ee3aeec5…, t1e 5a6d243f…, t2 4be062b8…, t3 232c2d7c…, t4 ed74ce70…, t5 23dce226…, t5l 02ed1731…, v1t f1042b80…,
v4 a4f78e7c…, v4t 2dbbdf56…, v4z cd432834…, v5 f773a3f6…, v5x 7af342b3…`. Die Saat-Prüfung der Sicherungen (§23.1)
war in allen Läufen bestanden.

**Lauf A** – `skripte/fuzz.sh 30 --neue-saat`, Saat `1792260436`, alle 12 Ziele parallel je 30 min, 20:07–20:37,
Wanduhr 1812 s, Exit 0 (`build/fuzz/lauf-20261017-200718/`):

| Ziel | Minuten | Eingaben | pro s | Ergebnisarten | Kanten (neu im Lauf) | Funde | Exit | langsamste Eingabe (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `datei` | 30.0 | 902'142 | 501 | 34 | 5846 (+830) | 0 | 0 | 0.82 |
| `inhalt` | 30.0 | 240'062 | 133 | 17 | 13182 (+1740) | 0 | 0 | 2.76 |
| `notfall` | 30.0 | 31'659 | 18 | 17 | 2965 (+1329) | 0 | 0 | 2.64 |
| `karte` | 30.0 | 5'121'124 | 2'845 | 3 | 1049 (+619) | 0 | 0 | 0.13 |
| `csv` | 30.0 | 86'428 | 48 | 17 | 1840 (+1584) | 0 | 0 | 0.96 |
| `totp` | 30.0 | 3'522'876 | 1'957 | 16 | 1271 (+1016) | 0 | 0 | 0.12 |
| `cbor` | 30.0 | 7'632'419 | 4'240 | 81 | 1385 (+877) | 0 | 0 | 0.12 |
| `ctaphid` | 30.0 | 70'143 | 39 | 218 | 2958 (+1360) | 0 | 0 | 0.81 |
| `hwdatei` | 30.0 | 26'322'201 | 14'623 | 9 | 799 (+375) | 0 | 0 | 0.15 |
| `sicherung` | 30.0 | 256'771 | 143 | 45 | 12045 (+1209) | 0 | 0 | 0.20 |
| `autofill` | 30.0 | 13'442'804 | 7'468 | 4 | 733 (+478) | 0 | 0 | 0.17 |
| `vernichtung` | 30.0 | 9'074 | 5 | 3228 | 19065 (+1470) | 0 | 0 | 0.64 |
| **Summe** | **6.00 h** | **57'637'703** | | | | **0** | | |

Weil `vernichtung` mit rund 5 Eingaben/s das langsamste Ziel ist (echte Dateien mit `F_FULLFSYNC`, mehrere Argon2 je
Eingabe), liefen die Ziele mit Selbstvernichtung zusätzlich mit anderen Saaten (gleicher Saat-Korpus, gleichzeitig,
20:38–21:08):

| Lauf | Saat | Ziel | Minuten | Eingaben | pro s | Ergebnisarten | Kanten (neu) | Funde | Exit |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| B (`lauf-20261017-203809`) | `1792262286` | `vernichtung` | 30.0 | 7'075 | 4 | 2584 | 19116 (+1679) | 0 | 0 |
| B | `1792262286` | `inhalt` | 30.0 | 309'083 | 172 | 17 | 13167 (+1722) | 0 | 0 |
| B | `1792262286` | `sicherung` | 30.0 | 119'779 | 67 | 45 | 12042 (+1359) | 0 | 0 |
| C (`lauf-20261017-203818`) | `1792262401` | `vernichtung` | 30.0 | 7'366 | 4 | 2635 | 19096 (+1505) | 0 | 0 |
| D (`lauf-20261017-203827`) | `1792262402` | `vernichtung` | 30.0 | 7'412 | 4 | 2693 | 19102 (+1511) | 0 | 0 |
| **Summe** | | | **2.50 h** | **450'715** | | | | **0** | |

`sicherung` lief in Lauf B halb so schnell wie in Lauf A (67 statt 143/s): Drei `vernichtung`-Prozesse schreiben
gleichzeitig mit `F_FULLFSYNC`.

**Summe je Ziel (Langlauf Runde 3):**

| Ziel | Stunden | Eingaben | Kanten am Ende | Funde |
|---|---:|---:|---:|---:|
| `vernichtung` | 2.00 | 30'927 | 19'065–19'116 | 0 |
| `inhalt` | 1.00 | 549'145 | 13'167–13'182 | 0 |
| `sicherung` | 1.00 | 376'550 | 12'042–12'045 | 0 |
| übrige 9 Ziele | je 0.50 | 57'131'796 | wie Lauf A | 0 |
| **Summe** | **8.50** | **58'088'418** | | **0** |

Mit Runde 1 und 2 zusammen: 20.4 Fuzz-Stunden, 221.9 Mio. Eingaben, im Langlauf kein Fund im Produktcode. Nicht
eingerechnet sind die Läufe beim Aufbau (16:56–20:04, Code in Arbeit, samt Proben): 27 Läufe, 5.6 Fuzz-Stunden,
38.5 Mio. Eingaben.

**Was `vernichtung` durchlaufen hat (Summe A–D):**

- Vorgänge mit Vernichtung (Totmann-Prüfung am Anfang jedes Entsperrens bzw. Einspielens eingeschlossen):
  `checkDeadman` 2199, Entsperren mit falschem Passwort 878, mit dem Vernichtungs-Passwort 8555, mit dem echten
  Passwort 659 bzw. mit anschliessendem `removeDestroyedEntries` 42, mit dem Vernichtungs-Passwort einer anderen Saat
  604, Einspielen mit falschem Passwort 23 bzw. mit dem Vernichtungs-Passwort 57.
- Welt: V fehlt 1057, V von B dazu 1053, V-Material von B unter dem Namen von A 1087, Tresordatei kaputt 881 bzw.
  weg 854, Rollback 966 (1237-mal „Rollback-Verdacht“ gemeldet), Schreibschutz 1041 (4010 vorhergesagte
  Schreibfehler), Vernichtungs-Schicht wirft 792 / tut nichts 674 / löscht und wirft 686, Wettlauf 951 (davon 384-mal
  `zustand.json` zwischen Probe und Vermerk wirklich getauscht).
- `zustand.json`: 18 192 gültig, 10 352 verworfen; 224 in anderer Zahlschreibweise angenommen und 558 verworfen –
  jedes Mal Feld für Feld gleich wie der eigene Leser; einmal die bekannte Nachsicht von JSONDecoder.
- Invariante 6 (Rotation entwertet alte Umschläge) 18 458-mal geprüft, Invariante 7 (Sicherungen nach dem Markieren)
  2252-mal.
- 75-mal löschte ein manipulierter Zustand im gesperrten Zustand den Eintrags-SE-Schlüssel: die dokumentierte Grenze
  (§8.1, SICHERHEIT.md „Zustand im Container ist nicht geheim“), kein Fund.

Weitere Ziele: `inhalt` deckte manipulierte versiegelte Einträge auf – nur `factorUnavailable(.secureEnclave)`,
`wrongPassword`, `wrongCard`; `sicherung` vernichtete beim Einspielen 5567-mal über den Zähler (Lauf A+B);
`ctaphid` brach 5871-mal während des stillen Wartens auf Berührung ab; beim Abbruch aus dem zweiten Thread lag 835-mal
genau eine Anfrage zwischen Prüfung und Senden (jedes Mal mit CTAPHID_CANCEL), 3-mal war die Antwort schon unterwegs.

### 8.5 Abschluss: Tests, Sanitizer, Gegenprobe, Bau

Abschluss am 17.10.2026, 21:19–21:50, nach dem Langlauf. Am Code geändert wurde dabei nur die Zeitschranke eines Tests
(§8.2, Testumgebung); Produktcode, Fuzzer und `fuzz.sh` sind unverändert.

| Prüfung | Umfang | Ergebnis |
|---|---|---|
| `swift test` | 496 Tests in 70 Suiten: SiegelCoreTests 369 (56), SiegelHardwareTests 114 (13), SiegelAutofillTests 13 (1); 43 s inkl. Bau | **grün**, 0 Warnungen, übersprungen nur die Handtests; Suite „Fuzz-Befunde: Selbstvernichtung“ (9 Tests) 11 s |
| `skripte/sanitizer.sh address` | `swift test --sanitize=address`, 496 Tests, 130 s | bestanden, ASan 0, UBSan 0 |
| `skripte/sanitizer.sh thread` | `swift test --sanitize=thread`, 496 Tests, 164 s | bestanden, TSan 0 |
| `referenz/gegenprobe.sh` | v1 + v2 Beispieldatei, 119 Prüfpunkte, 19 s | **alles stimmt**, Exit 0 |
| `./build.sh` | Grep-Sperren (133 Dateien), Release, ad-hoc-Signatur, 6 Entitlements, Bündelinhalt, Installation; 42 s | grün, Release-Bau 38 s mit 0 Warnungen. Vorher lief keine Siegel-Instanz |
| App starten/beenden | `~/Applications/Siegel.app` geöffnet, `skripte/fenster_pruefen.swift`, Beenden per Apple Event „quit“ | 1 Fenster (902×588), `sharingState 0`; nach wenigen Sekunden sauber beendet, kein Absturzbericht; App-Container unverändert (nur `.lock`, kein Tresor angelegt) |

Der Weg dahin, ehrlich: Der erste Durchgang lief unter Fremdlast auf dem Mac (Load bis 86 bei 18 Kernen, Swap
10.8 GB belegt). `swift test` war grün (91 s), ASan bestanden (208 s inkl. Neubau), aber **TSan scheiterte** an einem
Test: „Zufälliger Code → kein Treffer“ überschritt seine feste Schranke von 60 s – ohne eine einzige
Sanitizer-Meldung. Behoben in der Testumgebung (§8.2). Ein `swift test` direkt danach, noch unter Last (149 s), scheiterte
einmal an `laufzeitMitNeuenMustern` (252 ms statt < 250 ms, eine Debug-Laufzeitgrenze); bei ruhigem System lief derselbe
Stand in 43 s grün, danach ASan und TSan wie in der Tabelle. Diesen lastempfindlichen Test habe ich nicht geändert.
Direkt nach dem Langlauf (vor diesem Abschluss) waren `swift test` und beide Sanitizer mit demselben Produktcode schon
einmal grün (ASan 100 s, TSan 168 s).

### 8.6 Grenzen (ehrlich)

- `vernichtung` ist langsam (4–5 Eingaben/s unter ASan); 30 927 Eingaben in 2 h sind wenig gegenüber den Millionen der
  Parser-Ziele. Die Kanten wachsen am Ende kaum noch, die Ergebnisarten schon (jede Kombination von Vorgängen ist eine
  eigene Art): Lange Vorgangsfolgen sind nicht erschöpfend abgedeckt. Ein Nachtlauf nur dieses Ziels wäre der nächste
  Schritt (`skripte/fuzz.sh 120 --ziele vernichtung`).
- Die Läufe B–D teilen den Saat-Korpus von Lauf A und unterscheiden sich nur in der Saat-Zahl. Nach `--neue-saat` passen
  ältere Fund-Dateien von `vernichtung` und `sicherung` (in `funde/erledigt-20261017`, `proben-20261017`) nur noch
  zum Saat-Ordner ihres damaligen Laufs.
- Die Vernichtungs-Saaten nutzen ein Software-V und Platzhalter statt Secure-Enclave-Schlüsseln (keine Biometrie,
  keine Dialoge); die echte Schicht `SecureEnclaveFactor.destroy` ist nicht gefuzzt, nur ihr Fehlverhalten
  nachgebildet.
- Dass ein manipulierter `zustand.json` im gesperrten Zustand eine Vernichtung auslösen kann, ist gewollt dokumentiert
  und wird darum nicht als Fund gemeldet.
- Die Wirksamkeit der Abbruch-Invarianten in `ctaphid` ist mit zwei Proben belegt (p8, x4); der echte
  Sicherheitsschlüssel bleibt ungeprüft (Emulator).
- Tests mit Wanduhr-Grenzen sind lastempfindlich: `laufzeitMitNeuenMustern` (Debug-Grenze 250 ms) scheiterte einmal
  unter Fremdlast knapp. Abschlussläufe darum bei ruhigem System fahren (`uptime`).
- Die Zusammenfassung von `fuzz.sh` listet alle Dateien im Ordner `funde/`, auch ältere (so in
  `lauf-20261017-200110`: fünf Proben-Dateien, der Lauf selbst 0 Funde); massgeblich sind die Spalte „Funde“ und der
  Exit-Code.
- Im Temp-Ordner liegen 32 leere Ordner `siegelfuzz-vernichtung-*` und `siegelfuzz-sicherung-*` von abgebrochenen
  Läufen beim Aufbau (16:34–17:46, vor dem Aufräumen per `atexit`); keiner trägt `chflags uchg`, der Temp-Cleaner
  entfernt sie. Nicht von Hand gelöscht.

### 8.7 Reproduktion Runde 3

```bash
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
skripte/fuzz.sh 30 --neue-saat --saat 1792260436                 # Lauf A (Saat-Korpus wie oben)
skripte/fuzz.sh 30 --ziele vernichtung,inhalt,sicherung --saat 1792262286
skripte/fuzz.sh 30 --ziele vernichtung --saat 1792262401
skripte/fuzz.sh 30 --ziele vernichtung --saat 1792262402
swift test && skripte/sanitizer.sh && referenz/gegenprobe.sh
./build.sh
```

`--neue-saat` erzeugt Salze und Schlüssel neu; gleiche Eingabefolgen gibt es nur mit dem Saat-Korpus des Laufs
(`build/fuzz/saat/`, SHA-256 oben). Geändert in Runde 3: Produktcode im Kern (§8.2, SPEC v4.5), Fuzzer
(`Sources/SiegelFuzz/`: Saat, ZielVernichtung mit Leser, Modell und Ablauf, ZielCTAPHID, ZielInhalt, ZielSicherung,
Haupt), `skripte/fuzz.sh`, Tests (`KernVernichtungFuzzBefundeTests.swift`; im Abschluss die Zeitschranke in
`KernNotfallcodeTests.swift`), Dokumentation (`SPEC.md` §12, `KERN-NOTIZEN.md`, `SICHERHEIT.md`, `FUZZ-NOTIZEN.md`,
dieser Bericht, `README.md`, `LIESMICH.md`).
