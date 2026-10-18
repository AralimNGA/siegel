# Siegel für Windows – Stand Etappe 1

Stand 18.10.2026. Bindend sind `SPEC-WINDOWS.md` (wie unter Windows umgesetzt wird) und `../SPEC.md` (Format,
Kryptografie, Regeln, v4.8). Diese Datei sagt, was da ist, wie man baut und testet und womit bewiesen ist, dass Mac und
Windows dieselben Tresore lesen.

## Was Etappe 1 liefert

Etappe 1 ist der **plattformneutrale Teil** (läuft auf dem Mac und unter Windows in `dotnet test`). Eine Oberfläche gibt
es noch nicht: die WinUI-3-App (`src/Siegel.Windows/`) mit Windows Hello, Fensterschutz und MSIX ist Etappe 2, QR-Karte,
FIDO2, Kit-Druck und die Stufen 3–5 in der App Etappe 3 (`SPEC-WINDOWS.md` W0).

| Teil | Inhalt |
|---|---|
| `src/Siegel.Core/` | Kern wie `../Sources/SiegelCore/Kern/`: Format v1 lesen, v2 lesen und schreiben, Argon2id mit Grenzen, Mehrfaktor-Ableitung, Slots, Inhalts-JSON bytegleich zu Swift, Notfallcode mit Korrektur, Shamir 2 aus 3, CardCode, Eintrags-Schutz 1–5, Stufen und Faktoren, Sicherungen, Rollback-Wächter, Bericht, CSV/KeePass-Export, Selbstvernichtung. Dazu die **Windows-Hello-Art** des Eintrags-Gerätefaktors (W4.1). Notizen: `src/Siegel.Core/KERN-NOTIZEN-CS.md` |
| `src/Siegel.Werkzeuge/` | Stärke-Schätzung (zxcvbn, bit-gleich zu Swift), Master-Passwort-Regel, Passphrase, Passwort-Generator, TOTP, CSV-Import/-Export, KeePass-Export (KDBX 4.1), Autofill-Abgleich; `Modell/Modell.cs` = gemeinsame Typen |
| `tests/Siegel.Core.Tests/` | xUnit: `Kern/` (Format, Krypto, Fixtures, Interop, Hygiene), `Tresor/` (Tresor-Schicht, Hello, Vernichtung, Befunde, Werkzeuge im Kern), `Werkzeuge/` (Korpus-Gleichheit, Vektoren) |
| `tests/Fixtures/` | eingefrorene Interop-Dateien: `cs_*` schrieb der C#-Kern, `swift_*` der Swift-Kern; Werte in `tests/Fixtures/README.md`. **Nie ändern** |
| `skripte/` | `listen_exportieren.py` (Wortlisten und Unicode-Tabelle aus den Swift-Quellen), `korpus_erzeugen.py` (Stärke-, Graphem-, Autofill-Korpus mit Swift-Erwartung), `sperren_windows.sh`/`.py` (Grep-Sperren W3) |

Pakete (exakt gepinnt, Lock-Dateien): libsodium 1.0.22, BouncyCastle.Cryptography 2.7.0, xunit 2.9.3,
xunit.runner.visualstudio 3.1.4, Microsoft.NET.Test.Sdk 17.14.1. Keine weiteren.

## Bauen und testen auf dem Mac

Das .NET-SDK 10.0.402 liegt in `~/.dotnet` (nicht im PATH):

```
export DOTNET_ROOT=~/.dotnet PATH=~/.dotnet:$PATH DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
cd windows
dotnet build                      # Debug, 0 Warnungen (Warnungen sind Fehler)
dotnet test                       # 589 Tests, etwa 70 s auf dem M5 Max
dotnet build -c Release && dotnet test -c Release   # 251 Tests + 1 Hinweis (Kern-Tests brauchen den Debug-Bau)
skripte/sperren_windows.sh        # kein Console/Debug/Trace/ICU-Normalisierung, nach aussen nur SiegelException (Exit 1 bei Fund)
```

- Tests mit echtem Argon2 (256 MiB bis 1 GiB) laufen nacheinander in der Sammlung `EchteProfile`; die übrigen nutzen
  die Testschalter des Debug-Baus (wie Swift `@testable`).
- Die Python-Gegenproben in den Tests laufen nur, wenn Python 3.12 von python.org
  (`/Library/Frameworks/Python.framework/Versions/3.12/bin/python3`) und Homebrew-libsodium da sind; sonst gehen sie
  ohne Prüfung durch. Auf diesem Mac sind beide vorhanden.
- Swift-Seite der Beweise: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test` im Paketordner
  (517 Tests, etwa 40 s), `referenz/gegenprobe.sh` (Python liest Mac- und C#-Dateien).
- Aktualität der aus Swift erzeugten Daten (Exit 0 = aktuell):
  `python3 windows/skripte/listen_exportieren.py --pruefen` und `python3 windows/skripte/korpus_erzeugen.py --pruefen`
  (beide rufen das Swift-Hilfsprogramm `SiegelStaerkeExport` auf, brauchen also Xcode).

## Bauen und testen unter Windows (ThinkPad oder Render-PC)

Voraussetzung: .NET-SDK 10 (x64 oder arm64). Das Repo samt `Tests/` und `referenz/` muss vollständig da sein: die Tests
suchen die Mac-Fixtures (`../Tests/SiegelCoreTests/Fixtures/`) und `../referenz/` von `bin/` aus aufwärts.

```
cd windows
dotnet restore --locked-mode      # nur die gepinnten Pakete (Hash-geprüft)
dotnet build
dotnet test
python windows\skripte\sperren_windows.py   # falls Python da ist; sonst prüft KernHygieneTests dasselbe
```

- libsodium kommt aus dem NuGet-Paket (`runtimes/win-x64` bzw. `win-arm64`), keine Installation nötig.
- **Noch nie unter Windows gelaufen** (offen für Etappe 2): die Windows-Zweige im Kern (`MoveFileExW` mit
  `MOVEFILE_WRITE_THROUGH`, `\\?\`-Pfaden und Wiederholung bei fremden Sperren, ACL für neu angelegte Ordner,
  `NotContentIndexed`, `ERROR_FILE_EXISTS`) sind bisher nur auf dem Mac kompiliert und über die plattformneutralen Tests
  abgedeckt. Der erste `dotnet test` auf dem PC ist der Beweis; die Tests `RobustBefundeWindowsTests.Windows_…` (Sperre
  wie ein Virenscanner, ACL neuer und bestehender Ordner) und `Tiefer_Ordner_ueber_260_Zeichen` prüfen dort die
  Windows-Zweige selbst.
- Ohne Python überspringen sich die Python-Gegenproben; der macOS-Test mit `chflags` (Befund vernichtung-5) prüft unter
  Windows nichts (ein Gegenstück mit Verweigern-ACL fehlt noch).

## Interop-Beweise

| | Richtung | Datei(en) | Test |
|---|---|---|---|
| (a) | C# → Swift | `cs_v2_stufe_a.siegel` (Stufe 5), `cs_v2_beispiel.siegel` (Stufe 4, Schutz 1–5 der Mac-Art, 2 aus 3) | `../Tests/SiegelCoreTests/Interop/CSharpFixtureTests.swift`: Passwort + Software-Faktoren, Inhalt gegen `referenz/erwartet_v2_beispiel.json` bzw. README, jeden Eintrag aufdecken (Provider-Aufrufe gezählt), Papierkorb, Weiterschreiben, `checkRecoveryShares` jedes Paar, `recover(shares:)` |
| (a) | C# → Swift | `cs_v2_hello.siegel` (Windows-Hello-Art), `cs_inhalt_hello.json` (V der Hello-Art) | gleiche Suite + `KernWindowsHelloTests`: Einträge mit Gerätefaktor sind ein **anderes Gerät** (`factorUnavailable(.secureEnclave)` ohne Provider-Aufruf), Versiegeln verweigert, Notfallweg öffnet alles, JSON bytegleich neu kodiert, Mischformen beschädigt |
| (a) | Swift → C# | `swift_v2_aus_cs.siegel`, `swift_inhalt_stufe_b.json` (Swift v4.5), `swift_hello_aus_cs.siegel` (Swift v4.6 schrieb den Hello-Tresor weiter) | `SwiftInteropTests`, `CsHelloTests`: lesen, bytegleich neu kodieren, alle Hello-Einträge wieder über Windows Hello aufdecken, Siegel unverändert |
| (a) | Swift → C# | `swift_fffe_eintrag.siegel`, `swift_fffe_master.siegel` (U+FFFE), `swift_kirat_master.siegel` (Unicode 16, NFD) – Swift v4.6 | `SwiftUnicodeTests` (C#) und `SwiftUnicodeFixtureTests.swift` (Mac): entsperren, reuseTag wie Swift, speichern, importieren, Notfallweg; Befunde krypto-1/2/4 |
| (b) | C# → Python | `cs_v2_stufe_a.siegel`, `cs_v2_beispiel.siegel`, `cs_v2_hello.siegel` | `referenz/gegenprobe.sh` (Kopf, Passwortweg, Inhalt, Hello-Felder, gekippte Bytes, falsches Passwort) und `CsFixtureTests`/`CsBeispielTests`/`CsHelloTests.Python_…` |
| (c) | Mac → C# | `../Tests/SiegelCoreTests/Fixtures/v1_beispiel.siegel`, `v2_beispiel.siegel` | `BeispielDateiTests`, `EchteProfileTests`: echtes Argon2, Passwort + Faktoren und Notfallcode bzw. jedes Paar Teile, Inhalt = `referenz/erwartet_v*.json`, v1 bytegleich neu kodiert |
| (d) | Stärke Swift = C# | 11 161 Passwörter, 20 000 Graphem-Folgen, 12 000 Autofill-Paare, 6 000 Titel | `StaerkeKorpusTests` u. a.: je Passwort gleiche Bits (\|Δ\| ≤ 1e-9), Stufe, Zeichenzahl und Regel; `korpus_erzeugen.py --pruefen` rechnet die Swift-Seite neu |
| (d) | Normalisierung Swift = C# | 69 000 Zeichenketten (Foundation-NFC, `PasswordNormalizer`), 68 000 Paare (Swift `String ==`) | `NormalisierungTests`: gleiche Bytes je Fall, ohne ICU (Tabelle `swift_nfc.txt.gz`); `korpus_erzeugen.py --pruefen` |
| (e) | KDBX C# → Python | KeePass-Export aus C# | `ReferenzPythonTests` (Python-Referenz liest byte-genau, falsches Passwort abgelehnt); `WerkzeugeImKernTests` (Export über den Tresor, unabhängiger KDBX-Leser, Schutz 4/5 fehlen) |

Byte-Kipp-, Shamir-, Karten-, TOTP-, CSV- und Generator-Vektoren wie auf dem Mac: `ByteKippTests`, `ShamirTests`,
`CardCodeTests`, `TotpTests`, `CsvImportTests`, `PasswordGeneratorTests` u. a.

## Windows-Hello-Art und Austausch mit dem Mac

- Stufe 1 und alle Faktoren ausser dem Gerätefaktor sind austauschbar (W4.4). Richtet Windows den Eintrags-Gerätefaktor
  ein (Windows Hello), schreibt der C#-Kern die neue Art (`factors.windowsHello`, `hello` im Siegel, Format in
  `SPEC-WINDOWS.md` W12 W1.1). Ein Mac ab **v4.6** öffnet einen solchen Tresor, zeigt die Einträge, lässt offene Felder
  ändern und meldet für Einträge mit Gerätefaktor „anderes Gerät“; der Notfallweg öffnet alles (danach Stufe 1).
  Mac-Versionen bis v4.5 halten ihn für beschädigt.
- Unter Windows braucht jedes Versiegeln eine Windows-Hello-Signatur (Mac: nur der öffentliche Schlüssel). Die
  versiegelnden Änderungen heissen darum `…Async` und holen die Signaturen über `IEntryFactorProvider`.

## Fixtures neu erzeugen (nur von Hand, danach einfrieren)

Nur wenn eine neue Datei dazukommt – bestehende Dateien werden nie überschrieben:

```
SIEGEL_CS_FIXTURE_ZIEL=<Ordner> dotnet test --filter "FullyQualifiedName~CsFixtureTests.Erzeugen_nur_von_Hand"
SIEGEL_CS_BEISPIEL_ZIEL=<Ordner> dotnet test --filter "FullyQualifiedName~CsBeispielTests.Erzeugen_nur_von_Hand"
SIEGEL_CS_HELLO_ZIEL=<Ordner> dotnet test --filter "FullyQualifiedName~CsHelloTests.Erzeugen_nur_von_Hand"
SIEGEL_SWIFT_HELLO_ZIEL=<Datei> swift test --filter CSharpFixtureTests      # im Paketordner
```

Danach Werte und SHA-256 in `tests/Fixtures/README.md` eintragen.

## Offen für Etappe 2

- WinUI-3-App: `CoreEnvironment.IsUiThread` setzen, Datenort `%LOCALAPPDATA%\Siegel`, `FileRollbackGuard`,
  Löschschicht über `KeyCredentialManager.DeleteAsync`, BitLocker-Hinweis, `SetProcessWorkingSetSize` für `VirtualLock`,
  Windows-Hello-Anbieter (`WindowsHelloSecretAsync`), Oberflächentext „Windows Hello“ statt „Fingerabdruck“
  (`FactorKindExtensions.Title()` liefert noch den Mac-Text).
- `SICHERHEIT-WINDOWS.md` (ML-KEM über BouncyCastle, `VirtualLock`-Grenze, RSA-2048 nicht post-quanten, Hello-PIN).
- Erster `dotnet test` unter Windows; Gegenstück zum `chflags`-Test mit Verweigern-ACL.
- Bedienung der Hello-Art bei grossen Importen in Stufe 4/5 am Gerät messen (eine Abfrage je Eintrag?).
