# Siegel – Lizenzen und Drittkomponenten

Stand 17.10.2026 (Befund #44: vollständig für alles, was in der App steckt oder beim Entwickeln benutzt wird).
Siegel selbst steht unter der **MIT-Lizenz** (Datei `LICENSE`, © 2026 Aralim). Alles, was nicht in dieser Datei
steht (Code, Logo, eigene Wortlisten, Kalender- und Ortsnamen der Passwort-Schätzung, Python-Referenz), ist eigenes
Werk und fällt unter diese Lizenz. Für die Windows-Version (`windows/`) kommt BouncyCastle (MIT) als Paket dazu.

## Übersicht

| Komponente | Version | Wo im Projekt | Lizenz | Steckt in der App |
|---|---|---|---|---|
| libsodium | 1.0.22 | `Vendor/Clibsodium.xcframework` (statisch gelinkt) | ISC | ja |
| zxcvbn: Algorithmus (Swift-Port) und Häufigkeitslisten | 4.4.2 | `Sources/SiegelCore/Staerke/Zxcvbn/`, `Staerke/Woerter/Liste*.swift`, Quellen in `skripte/woerter/quellen/zxcvbn/` | MIT (Rohdaten siehe unten, u. a. Wiktionary CC BY-SA) | ja |
| Webster's Second International (`/usr/share/dict/web2`) | macOS 26 | `Staerke/Woerter/ListeEnglischWeb2.swift` | gemeinfrei | ja |
| Öffentliche Domain-Suffixe (Auszug, 177 Einträge) | – | `Sources/SiegelCore/Werkzeuge/AutofillMatcher.swift` | Tatsachen; angelehnt an die Public Suffix List (MPL 2.0), siehe unten | ja |
| Formate KDBX 4.1 (KeePass) und otpauth-URI | – | `Werkzeuge/KeePassExport.swift`, `Werkzeuge/TOTP.swift` | Formatbeschreibungen, kein fremder Code | ja |
| RFC 4226, RFC 6238, RFC 4648, RFC 5869 (Testvektoren, Verfahren) | – | `Tests/SiegelCoreTests/Werkzeuge/TOTPTests.swift`, `Werkzeuge/TOTP.swift` | IETF Trust (BCP 78) | nur Verfahren |
| Apple-Frameworks und Swift-Laufzeit | macOS 26 | vom System | Teil von macOS | nein (vom System geladen) |

## Pflichten

ISC und MIT verlangen, dass der Copyright- und Erlaubnishinweis **in allen Kopien** der Software steht. Diese
Datei enthält beide Texte vollständig und ist die massgebliche Quelle. Die **Anzeige in der App** ist Aufgabe der
Oberfläche (Befund #44): Sie zeigt mindestens die beiden Blöcke „libsodium (ISC)“ und „zxcvbn (MIT)“ unten
wörtlich an (z. B. unter Einstellungen → Sicherheit → Lizenzen oder im Standardfenster „Über Siegel“ über eine
`Credits.html`, die `build.sh` vor dem Signieren ins Bundle legt und auf „Dan Wheeler and Dropbox“ und „Frank
Denis“ prüft). **Bevor Siegel.app weitergegeben wird**, muss diese Anzeige vorhanden sein.

Prüfliste für die Anzeige:
- [ ] libsodium: Copyright-Zeile „Copyright (c) 2013-2026 Frank Denis“ und der ganze ISC-Text.
- [ ] zxcvbn: beide Copyright-Zeilen (Rian Hunter; Dan Wheeler and Dropbox, Inc.) und der ganze MIT-Text.
- [ ] Hinweis „Wortlisten nach zxcvbn; Rohdaten aus Wikipedia/Wiktionary (CC BY-SA), US-Volkszählung, Mark Burnett“
      (freiwillig, aber ehrlich, siehe „Rohdaten hinter den Listen“).

## libsodium (ISC)

Statische Bibliothek aus der Homebrew-Bottle, übernommen mit `skripte/libsodium_holen.sh` (Herkunft und
SHA-256 in `Vendor/LIBSODIUM.txt`). Text unverändert aus `Vendor/LIBSODIUM-LICENSE.txt`, die das Skript aus
dem Homebrew-Paket kopiert:

```
/*
 * ISC License
 *
 * Copyright (c) 2013-2026
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
```

## zxcvbn (MIT)

Siegel enthält zweierlei aus zxcvbn 4.4.2 (Dan Wheeler, Dropbox):

- den **Schätz-Algorithmus**, nach Swift portiert (`Sources/SiegelCore/Staerke/Zxcvbn/`; die Tastatur-Graphen
  für QWERTZ-CH und QWERTY sind selbst aufgebaut), und
- sechs **Häufigkeitslisten** (`passwords`, `english_wikipedia`, `us_tv_and_film`, `surnames`, `male_names`,
  `female_names`), als generierte Swift-Literale.

Die Listen wurden nicht heruntergeladen, sondern unverändert aus der lokalen Chrome-Komponente kopiert:
`~/Library/Application Support/Google/Chrome/ZxcvbnData/3/`. Am 16.10.2026 nachgeprüft: Die SHA-256 der sechs
Dateien in `skripte/woerter/quellen/zxcvbn/` stimmen mit der Komponente überein (Werte in
`Sources/SiegelCore/Staerke/Woerter/HERKUNFT.md`).

**Herkunft des Lizenztexts:** In der Komponente `ZxcvbnData` liegt keine Lizenzdatei (nur `manifest.json`,
`manifest.fingerprint`, `_metadata/verified_contents.json`, die Listen und `ranked_dicts`). Chromium führt
zxcvbn in seinen Lizenzhinweisen als «C++ port of zxcvbn» (zxcvbn-cpp, die Fassung, die Chrome für die
Passwortprüfung nutzt). Der Wortlaut unten ist unverändert aus einer lokalen Kopie dieser Chromium-Hinweise
übernommen (nur `&quot;` als `"` geschrieben):
`~/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/ThirdPartyLegalNotices-Chromium.html`,
Eintrag «For C++ port of zxcvbn, an advanced password strength estimation library.».

```
Copyright (c) 2016 Rian Hunter
Copyright (c) 2012-2016 Dan Wheeler and Dropbox, Inc.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

Abgleich mit `skripte/woerter/quellen/zxcvbn/LIZENZ.txt`: gleicher MIT-Text, dort aber nur mit der Zeile
«Copyright (c) 2012-2016 Dan Wheeler and Dropbox, Inc.». Das ist der Hinweis des ursprünglichen zxcvbn. Die
Zeile von Rian Hunter gehört zum C++-Port. Beide Zeilen mitzuführen schadet nicht und deckt beide Lesarten der
Herkunft ab; für die Weitergabe diesen Text verwenden.

**Rohdaten hinter den Listen** (laut `LIZENZ.txt`; nicht mit der zxcvbn-Dokumentation abgeglichen und nicht
juristisch geprüft): Wortzählungen aus der englischen Wikipedia, Häufigkeiten aus Film- und TV-Untertiteln
über Wiktionary, Namen aus der US-Volkszählung (gemeinfrei), Passwörter aus der 10-Millionen-Sammlung von Mark
Burnett (2015, vom Autor zur freien Verwendung veröffentlicht). Siegel verwendet nur die Reihenfolge (Rang)
der Einträge, keine Texte. Ob reine Wortranglisten aus Wikipedia/Wiktionary unter deren CC-BY-SA-Lizenz
fallen, ist offen; zxcvbn und Chrome verteilen sie unter MIT.

**Wiktionary (CC BY-SA):** Die Liste `us_tv_and_film` beruht laut zxcvbn auf den Häufigkeitslisten aus
Wiktionary (Film- und TV-Untertitel), die unter CC BY-SA 3.0 stehen. Siegel enthält davon nur die Wörter in
Rangfolge, keine Texte. Ob eine Rangliste einzelner Wörter ein geschütztes Werk ist, ist offen; die ehrliche
Nennung (Prüfliste oben) kostet nichts und genügt der Namensnennung, falls sie nötig ist.

## Webster's Second International (`/usr/share/dict/web2`, gemeinfrei)

Englische Wörter ab 6 Buchstaben, die in keiner anderen Liste stehen, aus der Wortliste von macOS
(Webster's New International Dictionary, Second Edition, 1934). Die Begleitdatei `/usr/share/dict/README`
(BSD) hält fest: «The 1934 copyright has lapsed, according to the supplier.» Kein Hinweis nötig; die Herkunft
steht trotzdem in `HERKUNFT.md`.

## Öffentliche Domain-Suffixe (AutofillMatcher)

`AutofillMatcher.publicSuffixes` ist eine kleine, von Hand zusammengestellte Liste mehrteiliger öffentlicher
Suffixe (`co.uk`, `com.au`, `github.io` …, 177 Einträge). Die Einträge sind Domainnamen, also Tatsachen; die
Auswahl folgt der Public Suffix List von Mozilla (https://publicsuffix.org, MPL 2.0), die Datei selbst wurde nicht
kopiert. Sollte die Liste als Auszug gelten: MPL 2.0 verlangt für geänderte Dateien die Quellform – sie steht offen
in `AutofillMatcher.swift`.

## Formate, Standards und Testvektoren

- **KDBX 4.1** (KeePass-Export, `KeePassExport.swift`): nach der öffentlichen Formatbeschreibung von KeePass
  (Dominik Reichl) umgesetzt. Kein Code aus KeePass (GPL) oder KeePassXC (GPL) übernommen. Aus dem
  KeePassXC-Quelltext wurde am 17.10.2026 nur nachgesehen, welche Salzlängen beim Lesen erlaubt sind
  (`KDF_MIN_SEED_SIZE 8`, `KDF_MAX_SEED_SIZE 32` in `src/crypto/kdf/Kdf.h`), um die Verträglichkeit zu belegen.
- **otpauth-URI** (`TOTP.swift`): Format nach der „Key Uri Format“-Beschreibung von Google Authenticator; kein
  fremder Code.
- **RFCs** 4226 (HOTP), 6238 (TOTP), 4648 (Base32), 5869 (HKDF, in der Python-Referenz), 7539 (ChaCha20): Verfahren
  und die Testvektoren aus RFC 4226 Anhang D und RFC 6238 Anhang B (nur in den Tests). RFC-Texte stehen unter den
  Bedingungen des IETF Trust (BCP 78); Testvektoren sind Zahlenwerte und werden mit Quelle genannt.

## Apple-Frameworks und Swift (System)

Siegel nutzt nur Frameworks, die Teil von macOS 26 sind, und liefert keines davon mit: SwiftUI, AppKit,
Foundation, CryptoKit (ML-KEM-1024, X25519, SHA3-256, HKDF, HMAC-SHA1/256/512 für TOTP), CoreGraphics, ApplicationServices
(Druckerabfrage), Carbon.HIToolbox (sichere Tastatureingabe), UniformTypeIdentifiers, Observation,
Synchronization, Darwin. Gebaut wird mit dem SDK aus Xcode 27 unter Apples Xcode- und SDK-Lizenzvereinbarung.
Die Swift-Standardbibliothek und -Laufzeit sind ebenfalls Teil von macOS; Swift steht unter Apache 2.0 mit
«Runtime Library Exception», die für übersetzte Programme keinen Hinweis verlangt. Die Schriften SF Pro und
SF Mono kommen vom System und werden nicht eingebettet.

## Nur zum Entwickeln (nicht in der App)

| Werkzeug | Wozu | Lizenz |
|---|---|---|
| Xcode 27 mit Swift-Toolchain und swift-testing | Bau und Tests | Apple-Lizenz bzw. Apache 2.0 |
| Homebrew `libsodium` | Quelle für `skripte/libsodium_holen.sh` | ISC (siehe oben) |
| Python 3 (Standardbibliothek) | `skripte/woerter/listen_bauen.py`, `design/bauen.py`, `referenz/siegel_referenz.py` | PSF |
| Homebrew `libsodium` (dynamisch, per `ctypes`) | nur die Python-Referenz `referenz/` (nicht in der App) | ISC (siehe oben) |
| Pillow (optional) | Prüfbild `design/render/vorher-nachher.png` in `design/bauen.py` | MIT-CMU (HPND) |
