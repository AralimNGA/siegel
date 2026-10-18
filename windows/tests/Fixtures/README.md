# Interop-Dateien des C#-Kerns (SPEC-WINDOWS W7) – nie ändern

`cs_*` schreibt der **C#-Kern**; der Swift-Kern und die Python-Referenz (`../../../referenz/`) müssen sie öffnen können.
`swift_*` schrieb der **Swift-Kern** (v4.5, `swift_hello_aus_cs.siegel` v4.6) für die Gegenrichtung; C# muss sie lesen
und das JSON bytegleich neu kodieren. Wie die Mac-Fixtures (`../../../Tests/SiegelCoreTests/Fixtures/`) sind alle nach dem
Erzeugen eingefroren. Die C#-Tests stehen in `../Siegel.Core.Tests/Kern/CsFixtureTests.cs`, `CsBeispielTests.cs`,
`CsHelloTests.cs` und `SwiftInteropTests.cs`; sie lesen die Werte unten aus dieser Datei (Spalte 2, in Backticks;
`CsBeispielTests` und `CsHelloTests` nur aus ihrem Abschnitt). Die Swift-Seite:
`../../../Tests/SiegelCoreTests/Interop/CSharpFixtureTests.swift` (seit der Integration fest im Repo), die Python-Seite:
`../../../referenz/gegenprobe.sh`.

| Datei | Von | Inhalt |
|---|---|---|
| `cs_v2_stufe_a.siegel` | C# (Stufe A) | Stufe 5, alle Faktoren, 2 aus 3, drei offene Einträge (Abschnitt unten) |
| `cs_v2_beispiel.siegel` | C# (Stufe B) | Stufe 4, Notfall 2 aus 3, Einträge Schutz 1–5 (versiegelt mit festen Software-Faktoren), TOTP, Verlauf, ein gelöschter Eintrag (Abschnitt unten) |
| `swift_v2_aus_cs.siegel` | Swift | `cs_v2_stufe_a.siegel`, von Swift entsperrt und mit einem neuen Eintrag „Von Swift“ (Passwort `Geheim-123`, Schutz 2 versiegelt, Notfall-Gruppe, `meta` für alle) gespeichert: Generation 2, gleiches Passwort, gleiche Faktoren, gleiche Teile; SHA-256 `8716d4047941c8dc98d079aa4fec58dd00662576f05ab49e8741bc4c23ee1308` |
| `swift_inhalt_stufe_b.json` | Swift | Klartext-JSON (ohne Polster) eines Swift-Testtresors der Stufe 5 mit Schutz 2–5, vernichtbarem Eintrag, Vernichtungs-Passwort, Totmann 30 Tage, Zähler 20, gelöschtem Eintrag und Sonderzeichen; SHA-256 `c0ae0e5fbeaaa1727e996fdeb0c18490fd70a0ccba9325ef4f721f46d6377595` |
| `cs_v2_hello.siegel` | C# (Integration) | wie `cs_v2_beispiel.siegel`, aber Eintrags-Gerätefaktor der **Windows-Hello-Art** (W4.1); alle Siegel mit `hello` statt `se` (Abschnitt unten) |
| `cs_inhalt_hello.json` | C# (Integration) | Klartext-JSON (ohne Polster) einer Stufe 4 der Windows-Hello-Art mit **V der Windows-Hello-Art**, einem vernichtbaren Eintrag, Vernichtungs-Passwort, Totmann 30 Tage, Zähler 20, gelöschtem Eintrag (Abschnitt unten) |
| `swift_hello_aus_cs.siegel` | Swift (v4.6) | `cs_v2_hello.siegel`, vom Swift-Kern entsperrt und weitergeschrieben (Abschnitt unten) |
| `swift_fffe_eintrag.siegel` | Swift (v4.6) | Stufe 1, Eintragspasswort und Verlauf mit U+FFFE (Befund krypto-1, Abschnitt unten) |
| `swift_fffe_master.siegel` | Swift (v4.6) | Stufe 1, Master-Passwort mit U+FFFE (Befund krypto-1, Abschnitt unten) |
| `swift_kirat_master.siegel` | Swift (v4.6) | Stufe 1, Master-Passwort mit U+16D67 U+16D67 (Unicode 16), Einträge mit Unicode-16-Zeichen und NFD (Befunde krypto-2/krypto-4, Abschnitt unten) |

Die beiden `swift_*`-Dateien entstanden am 18.10.2026 mit einer vorübergehenden Swift-Suite (Quelltext in
`../../src/Siegel.Core/KERN-NOTIZEN-CS.md`, Abschnitt „Interop-Beweis“), die zugleich `cs_v2_stufe_a.siegel` mit dem
Swift-Kern geöffnet hat (Passwort + Faktoren, `checkRecoveryShares`, `recover(shares:)`).

## `cs_v2_stufe_a.siegel` (Stufe A des C#-Kerns, Format v2, Stufe 5 „Festung“)

Erzeugt am 18.10.2026 vom C#-Kern (Stufe A) mit `CsFixtureTests.Erzeugen_nur_von_Hand` (nur von Hand, Umgebungsvariable
`SIEGEL_CS_FIXTURE_ZIEL`): `VaultCrypto.Rekey` (Kopf v2, Argon2id 256 MiB/t = 3, alle drei Faktoren, Notfall 2 aus 3) →
Inhalt v2 mit Grundschlüssel → `VaultCrypto.BuildFile`. Nur erfundene Einträge. Noch **ohne** versiegelte Einträge
(Eintrags-Schutz kam mit Stufe B: `cs_v2_beispiel.siegel`, Abschnitt unten).

| | |
|---|---|
| Formatversion | 2, Stufe 5 (factorMask = 7, recoveryScheme = 2) |
| KDF | Argon2id, m = 256 MiB (268 435 456 Byte), t = 3 |
| Master-Passwort | `Wq7!vTz#2pLm9@Xc4$Rb8&Hn6*Kd` |
| Teil 1 von 3 | `05JNX-WRBPA-XC60H-CBAAX-TXKNT-0AZF4-Q7Z9C-4AP52-V5D7A-RRDAZ-G9XRT-E` |
| Teil 2 von 3 | `09X66-X43YV-P0EME-S5C5Z-6VSF6-5CQBN-RH41R-1EGCG-6JZ50-6SE01-749ZW-A` |
| Teil 3 von 3 | `0E382-2FVSB-FB4R4-A0J4E-K48SD-TA0P7-A3KXM-D1FVQ-DZHBM-CY6RK-EZPKX-R` |
| Kit-Kennung | `8K09-66VB` |
| vaultID | `30BA11CE-0480-4A1B-B5B6-FD82D6B4F8D3` |
| Generation | 1 |
| Grösse | 19 985 Byte (Kopf 1773 = 1709 + 64 Byte Credential) |
| SHA-256 der Datei | `3c12350ee73bf1ffdbc2a8d3f5a28d70782c47ec9a1a3a35913bc60b4bb7bc76` |
| kdfSalt | `218b04ad83c375e85c2d10c428eec6d7` |
| cardTag | `269d3d9e` |
| Notfallkit bestätigt | ja (`recoveryConfirmedAt` gesetzt) |
| Faktor Secure Enclave (Hex) | `1111111111111111111111111111111111111111111111111111111111111111` |
| Faktor Karte (Hex) | `2222222222222222222222222222222222222222222222222222222222222222` |
| Faktor FIDO2 (Hex) | `3333333333333333333333333333333333333333333333333333333333333333` |

Faktor-Angaben im Kopf wie bei `v2_beispiel.siegel` des Mac: seKeyID `11111111-2222-4333-8444-555555555555`,
credentialID `44` × 64, fidoSalt `55` × 32. Inhalt: dieselben drei Einträge wie die Mac-Beispieldateien (Bibliothek
Bern, Velo-Club mit Verlauf `Rad&Weg-2026` und TOTP, Notiz mit Zeilenumbruch/Umlauten/«»), Stufe 5, Grundschlüssel
(`entryKey`), alle drei Eintrags-Faktoren wie beim Mac-Fixture (Eintrags-SE-Schlüssel keyID
`66666666-7777-4888-8999-AAAAAAAAAAAA` mit dem öffentlichen Schlüssel aus `v2_beispiel.siegel`; Karte aus q = `22` × 32;
Sicherheitsschlüssel: entrySalt `66` × 32, Ausgabe `77` × 32, Prüfwert aus `33` × 32), kein `meta` (das ergänzt der nächste
Speichervorgang).

Gegenproben (18.10.2026, auf dem Mac):
- Python-Referenz: `printf '%s' "$PW" | python3 -I referenz/siegel_referenz.py siegel windows/tests/Fixtures/cs_v2_stufe_a.siegel --se 11… --karte 22… --fido 33…`
  liest Kopf und Inhalt (auch als Test `CsFixtureTests.Python_Referenz_liest_die_CSharp_Datei`).
- Swift-Kern: `../../../Tests/SiegelCoreTests/Interop/CSharpFixtureTests.swift` (`stufeA`: Inhalt gegen
  `referenz/erwartet_v2_beispiel.json`, Weiterschreiben, Teile); zuerst mit einer vorübergehenden Suite, siehe
  `KERN-NOTIZEN-CS.md` (Abschnitt „Interop-Beweis“).

## `cs_v2_beispiel.siegel` (Stufe B des C#-Kerns, Format v2, Stufe 4 „Maximal“)

Erzeugt am 18.10.2026 vom C#-Kern (Stufe B) mit `CsBeispielTests.Erzeugen_nur_von_Hand` (nur von Hand, Umgebungsvariable
`SIEGEL_CS_BEISPIEL_ZIEL` = Ordner) über den **ganzen Tresor-Weg** (`VaultStore.Create` → `CommitRecovery` → Eintrag in
Stufe 1 → `PrepareRecovery(Shamir2Of3)` + `ChangeSecurityLevel(Maximal)` mit den festen Faktoren → fünf `Upsert` →
`Delete`), Testschalter `LevelKdfOverride` = 256 MiB/t = 3 und `Now` = 2026-10-18 10:00:00 UTC. Nur erfundene Einträge.

| | |
|---|---|
| Formatversion | 2, Stufe 4 (factorMask = 3, recoveryScheme = 2) |
| KDF | Argon2id, m = 256 MiB (268 435 456 Byte), t = 3 |
| Master-Passwort | `Fj8#qW2!xN5@tR9$kP3&vL6*hZ4m` |
| Teil 1 von 3 | `06YGZ-YXAW9-Z5KD3-YN8VT-1A3ZH-0D8ZG-THQ01-PRE3N-R2TWJ-9RN8C-EDHF3-4` |
| Teil 2 von 3 | `0BZ59-XFH33-V4CE1-C8VDW-J9CWA-3HZ9M-GEQ8P-W2PCX-QFH0F-JZMTG-MSVJH-4` |
| Teil 3 von 3 | `0CV98-1HH9T-7BNDF-BXDVE-WQHM3-2TDVQ-9V9MV-N73Y5-J8KB8-SNBA0-X5FVF-V` |
| Kit-Kennung | `XNXZ-QZ73` |
| vaultID | `0BEDA2B0-B055-4D1F-ADBD-E35461ED501A` |
| Generation | `10` |
| Grösse | `52689` |
| SHA-256 der Datei | `3d3a1655d7365ec4b6c7c020e23b8f1cc97d6ae765003e65cd1046f1d00e52f2` |
| kdfSalt | `2642042093d95ac533ceb824e218bb46` |
| cardTag | `755f1a71` |
| Notfallkit bestätigt | ja (`recoveryConfirmedAt` gesetzt) |
| Faktor Secure Enclave (Hex, Entsperren) | `1111111111111111111111111111111111111111111111111111111111111111` |
| Faktor Karte q (Hex, Entsperren und Einträge) | `2222222222222222222222222222222222222222222222222222222222222222` |
| Eintrags-SE-Schlüssel, privater Skalar (Hex) | `8888888888888888888888888888888888888888888888888888888888888888` |
| Sicherheitsschlüssel, Ausgabe zum Eintrags-Salz (Hex) | `7777777777777777777777777777777777777777777777777777777777777777` |
| Sicherheitsschlüssel, Ausgabe zum fidoSalt (Hex, nur Prüfwert) | `3333333333333333333333333333333333333333333333333333333333333333` |

Faktor-Angaben wie bei `v2_beispiel.siegel` des Mac: seKeyID `11111111-2222-4333-8444-555555555555` (Kopf); im Inhalt
Eintrags-SE-Schlüssel keyID `66666666-7777-4888-8999-AAAAAAAAAAAA` mit dem öffentlichen Schlüssel zum Skalar `88` × 32
(derselbe wie in `v2_beispiel.siegel`), Karte aus q = `22` × 32, Sicherheitsschlüssel credentialID `44` × 64,
fidoSalt `55` × 32, entrySalt `66` × 32 (Ausgabe `77` × 32). Der Sicherheitsschlüssel ist in Stufe 4 nur für Einträge
eingerichtet (nicht im Kopf). Zum Entsperren genügen Passwort + `11…` + `22…`; zum Aufdecken liefert die Plattform
ECDH mit dem Skalar `88…`, q und `77…`.

Einträge (Reihenfolge der Datei; alle `created`/`modified` = 2026-10-18 10:00:00 UTC):

| Titel | Schutz | Benutzer | Passwort | Weiteres |
|---|---|---|---|---|
| Bibliothek Bern | 1 (offen, in Stufe 1 angelegt) | `leserin.muster` | `Buecher-Regal-42!` | URL `https://bibliothek.example.ch`, Notiz „Ausweisnummer steht auf der Karte.“ |
| Velo-Club | 2 | `velofahrer` | `Kette+Sattel-77` | Verlauf `Rad&Weg-2026`, TOTP `otpauth://totp/Velo-Club:velofahrer?secret=JBSWY3DPEHPK3PXP&issuer=Velo-Club` |
| Krankenkasse | 3 | `versicherte.4711` | `Praemie-2027!` | Notiz „Versichertennummer 756.0000.0000.00“ |
| Bank Thun | 4 | `kunde-0815` | `Konto#Sicher-4` | Verlauf `Alt-Konto-3`, `Alt-Konto-2`; TOTP `otpauth://totp/Bank:kunde-0815?secret=KRSXG5CTMVRXEZLU&issuer=Bank`; Notiz mit «» |
| Krypto-Wallet | 5 | – | `Seed+Phrase-55` | Notiz mit Zeilenumbruch, Umlauten, «» und Gedankenstrich |
| Alter Shop | 3, **gelöscht** (`deletedAt` = 2026-10-18 10:00:00 UTC) | `kaeufer` | `Warenkorb-99` | Notiz „Konto gekündigt“ |

Inhalt: 5 versiegelte Einträge (Mac-Art, `se` = ephemerer P-256-Punkt), 3 Notfall-Gruppen (Masken {SE}, {SE, Karte},
alle), `meta` für alle 6, keine Schlüssel der Windows-Hello-Art (bytegleich zum Swift-Kern).

Gegenproben (18.10.2026, auf dem Mac): C# (`CsBeispielTests`: Werte, Entsperren über den Store, alle Einträge aufdecken,
Notfallweg mit jedem Paar Teile, Neukodieren bytegleich), Python-Referenz (Kopf und Inhalt, Test
`CsBeispielTests.Python_Referenz_liest_Kopf_und_Inhalt`, `../../../referenz/gegenprobe.sh`) und Swift-Kern
(`../../../Tests/SiegelCoreTests/Interop/CSharpFixtureTests.swift`, `beispiel`: jeden Eintrag aufdecken, Papierkorb, jedes
Paar Teile).

## `cs_v2_hello.siegel` (Windows-Hello-Art, Format v2, Stufe 4 „Maximal“)

Erzeugt am 18.10.2026 bei der Integration von Etappe 1 mit `CsHelloTests.Erzeugen_nur_von_Hand` (nur von Hand,
Umgebungsvariable `SIEGEL_CS_HELLO_ZIEL` = Ordner) über den ganzen Tresor-Weg wie `cs_v2_beispiel.siegel`
(`Create` → `CommitRecovery` → Eintrag in Stufe 1 → `PrepareRecovery(Shamir2Of3)` + `ChangeSecurityLevelAsync(Maximal)` →
fünf `UpsertAsync` → `Delete`), Testschalter `LevelKdfOverride` = 256 MiB/t = 3 und `Now` = 2026-10-18 11:00:00 UTC. Gleiche
Einträge wie `cs_v2_beispiel.siegel`, aber der **Eintrags-Gerätefaktor ist ein Windows-Hello-Schlüssel**
(`factors.windowsHello`, keyID `B6666666-7777-4888-8999-AAAAAAAAAAAA`, `factors.secureEnclave = null`); jedes Siegel mit
Gerätefaktor (5 Einträge, 3 Anker) trägt `"hello": {"salt", "version": 1}` statt `"se"`. Die Signatur ersetzt im Test ein
Software-Ersatz: roh = SHA-256(`"Siegel v2 windows hello entry"` ‖ HMAC-SHA256(Schlüssel `99` × 32, keyID ‖
Herausforderung)).

| | |
|---|---|
| Formatversion | 2, Stufe 4 (factorMask = 3, recoveryScheme = 2) |
| KDF | Argon2id, m = 256 MiB (268 435 456 Byte), t = 3 |
| Master-Passwort | `Rk5$wT9!bN2#qX7@mH4&zP8*vC3j` |
| Teil 1 von 3 | `06VAM-QNR4Y-C2AZ7-M7Z0C-QJGYH-VAAPK-JG3WC-9T66T-TVRRH-5AH9Y-S6YFG-M` |
| Teil 2 von 3 | `08RJR-NEEEG-H8EF7-DDX6F-9CDK7-3WAGS-7M4WY-E28NJ-RTZ5F-WV6W9-0RVZF-R` |
| Teil 3 von 3 | `0D6AF-98N8P-YH1X8-KBZ0Y-3611M-CATK2-V1RRG-3RD33-7XSEQ-MC2E0-8D618-5` |
| Kit-Kennung | `Q19F-W07N` |
| vaultID | `15467C6E-D6A8-456B-A31E-F62AFE0C10C5` |
| Generation | `10` |
| Grösse | `52689` |
| SHA-256 der Datei | `8c209465cc1a124fe9695db28718bbb7b9074ff9d70a4839cafc31030d322400` |
| kdfSalt | `f24fd23d543e895bee46f2e87161fc61` |
| cardTag | `a6b61c70` |
| Faktor Secure Enclave (Hex, Entsperren) | `1111111111111111111111111111111111111111111111111111111111111111` |
| Faktor Karte q (Hex, Entsperren und Einträge) | `2222222222222222222222222222222222222222222222222222222222222222` |
| Windows-Hello-Ersatz, HMAC-Schlüssel (Hex) | `9999999999999999999999999999999999999999999999999999999999999999` |
| Sicherheitsschlüssel, Ausgabe zum Eintrags-Salz (Hex) | `7777777777777777777777777777777777777777777777777777777777777777` |
| SHA-256 von cs_inhalt_hello.json | `70699a8d67b8c9a1f521ac47dfb6e5e2aeb0e2103eb4f8c01e197cc3cf554acf` |
| SHA-256 von swift_hello_aus_cs.siegel | `c91351a4947d9700958cae2f80934bfd71be4efb3c785891076c8e6922b1152d` |

Kopf: seKeyID `A1111111-2222-4333-8444-555555555555` (unter Windows der Windows-Hello-Schlüssel zum Entsperren; im Test der
feste Wert `11…`). Sicherheitsschlüssel nur für Einträge wie bei `cs_v2_beispiel.siegel` (credentialID `44` × 64, fidoSalt
`55` × 32, entrySalt `66` × 32, Prüfwert aus `33` × 32).

`cs_inhalt_hello.json` (gleicher Lauf, Testschalter-KDF, nur das JSON zählt): Stufe 4, Eintrags-Gerätefaktor Windows Hello,
Karte und Sicherheitsschlüssel; V der Windows-Hello-Art `{"keyID": "C7777777-8888-4999-8AAA-BBBBBBBBBBBB", "windowsHello": 1}`;
Einträge „Bank“ (Schutz 4, **vernichtbar**, Siegel an V mit `hello`), „Mail“ (2), „Wallet «Kalt»“ (5), „Alt/Weg“ (3,
gelöscht); Totmann 30 Tage, Zähler 20, Vernichtungs-Passwort eingerichtet.

`swift_hello_aus_cs.siegel`: `cs_v2_hello.siegel`, vom **Swift-Kern v4.6** entsperrt (Passwort + `11…`/`22…`) und mit
den Änderungen weitergeschrieben, die der Mac ohne Windows Hello darf (`CSharpFixtureTests.macAenderungen`, `TestHooks.now`
= 2026-10-18 12:00:00 UTC): Passwort von „Bibliothek Bern“ → `Mac-Eintrag-61!` (Verlauf `Buecher-Regal-42!`), „Velo-Club“
(versiegelt) umbenannt in „Velo-Club Bern“. Generation 12; Siegel, Anker und Eintrags-Faktoren unverändert.

Gegenproben (18.10.2026, auf dem Mac):
- C# (`CsHelloTests`): Werte, alle Einträge über den Windows-Hello-Ersatz aufdecken (die Mac-Art wird nie gefragt),
  Notfallweg, Neukodieren bytegleich, `cs_inhalt_hello.json` bytegleich, `swift_hello_aus_cs.siegel` lesen und aufdecken,
  Python-Referenz.
- Swift-Kern (`../../../Tests/SiegelCoreTests/Interop/CSharpFixtureTests.swift`): Einträge mit Gerätefaktor sind ein **anderes
  Gerät** (`factorUnavailable(.secureEnclave)` ohne Provider-Aufruf), Neu-Versiegeln ebenso, nichts wird geschrieben;
  offene Felder ändern geht und lässt die Siegel unverändert; Notfallweg öffnet alles; `cs_inhalt_hello.json` kodiert Swift
  bytegleich neu, Mischformen sind beschädigt.
- Python-Referenz: `referenz/gegenprobe.sh` (Kopf, Passwortweg, Inhalt, Manipulation).

## Swift-Tresore mit besonderen Zeichen (Befunde krypto-1, krypto-2, krypto-4)

Erzeugt am 18.10.2026 vom **Swift-Kern v4.6** (vor der Zeichenregel v4.7) mit einer vorübergehenden Suite
(`Tests/SiegelCoreTests/Interop/TempUnicodeFixtureErzeugen.swift`, danach entfernt): `VaultStore.create(masterPassword:,
kdf: 256 MiB/t = 3)` → `commitRecovery` → je Eintrag `upsert` (Benutzer `anna`, Adresse `https://<titel ohne
Nicht-Buchstaben, klein>.example.ch`, bei Verlauf erst das alte, dann das neue Passwort), `TestHooks.now` = 2026-10-18
10:00:00 UTC; danach öffnete der Swift-Kern jede Datei wieder. Nur erfundene Werte. Passwörter hier als Skalare (U+…),
die Tests schreiben sie mit `\u`-Escapes.

| | `swift_fffe_eintrag.siegel` | `swift_fffe_master.siegel` | `swift_kirat_master.siegel` |
|---|---|---|---|
| Master-Passwort | `Fffe-Eintrag#7qLm!2xV9@Rk4` | `Wq7!vTz#2pLm` U+FFFE `9@Xc4$Rb8&Hn` | `u,F?CfDuMlYWuJASPVQ*6GUG@O` U+16D67 U+16D67 |
| Notfallcode | `E1PFH-SGMRG-YD3S3-NT32K-YXW95-E7KDG-SVTYF-9T3BQ-JMYPC-ZV94Q-59Q38` | `NGBNZ-HA1DD-CDCYF-3XR13-KT37Z-EF1KS-605S3-3GZE2-S1XTE-TB1PZ-8TYJG` | `RH199-JT9ZE-D7Z38-J5A35-BEWEQ-6DK5K-4BGQ7-JDQ66-3TVKW-CNC73-GDJX0` |
| Kit-Kennung | `VDYE-Y1BD` | `1F96-GYQS` | `13CP-6B74` |
| vaultID | `CFA89C5D-014B-4A7B-823B-F2475FD86F6F` | `219F729D-3162-4782-B6CA-94044F60413D` | `07C0EAD7-1460-4FCF-8FBC-E20A6BBE331D` |
| Generation | 6 | 4 | 12 |
| Einträge (Passwort) | „Import FFFE“ (`neu` U+FFFE `wert`, Verlauf `abc` U+FFFE `def`), „Normal“ (`Normal-Passwort-1`) | „Normal“ (`Kette+Sattel-77`) | „Kirat“ (U+16D67 U+16D67 U+16D68 `-Kirat`), „Todhri“ (U+105D2 U+0307 `-Todhri`), „Gurung“ (U+1611E U+1611E `-Gurung`), „Tulu“ (U+113C2 U+113C2 `-Tulu`), „Zerlegt“ (`Cafe` U+0301 `-Passwort-12`, NFD) |
| Grösse | 19 921 Byte | 19 921 Byte | 19 921 Byte |
| SHA-256 | `7e518e61edafb7f8ab6d708d609b5b2c1de4d19af722c515a38cd9ea98c762ac` | `90cd463118fb026c11ca5288c5d2c856741f47147751e4a5ecc6542bba9d8979` | `1d1cc934303fa1bf841e3c856ecd6a0f67298296879c2b03c15c30f962654277` |

Gegenproben (18.10.2026, auf dem Mac):
- C# (`../Siegel.Core.Tests/Kern/SwiftUnicodeTests.cs`, echtes Argon2): U+FFFE im Eintragspasswort – entsperren, reuseTag
  wie von Swift, speichern, importieren, Notfallweg; U+FFFE im Master-Passwort – entsperren, `PasswordsMatch`,
  Passwortwechsel, Notfallweg, neuer Tresor; Unicode 16 – entsperren mit denselben Argon2-Bytes wie Swift (Foundation
  setzt U+16D67 U+16D67 nicht zusammen), reuseTag aller Einträge wie von Swift, NFC-Import des NFD-Eintrags übersprungen,
  neues Passwort mit Unicode-16-Zeichen abgelehnt (v4.7). Vor der Korrektur warf C# bei U+FFFE eine ArgumentException und
  lieferte bei Unicode 16 `WrongPassword`.
- Swift-Kern (`../../../Tests/SiegelCoreTests/Interop/SwiftUnicodeFixtureTests.swift`): öffnet alle drei weiter,
  Notfallweg; `create` mit dem Unicode-16-Passwort lehnt ab v4.7 `passwordTooWeak` ab.

