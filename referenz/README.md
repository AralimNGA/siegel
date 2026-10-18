# Python-Referenz (SPEC §21)

Eine zweite, unabhängige Umsetzung der Siegel-Formate in Python. Sie ist **nur aus `SPEC.md`** geschrieben, nicht
aus dem Swift-Code abgeleitet. Stimmen Swift und Python überein, ist ein Fehler, der in beiden gleich steckt, sehr
unwahrscheinlich – und ein Tresor bleibt auch dann lesbar, wenn es Siegel einmal nicht mehr gibt.

| Datei | Zweck |
|---|---|
| `siegel_referenz.py` | Leser für `.siegel` (Format v1 und v2, Passwortweg) und KDBX 4.x (KeePass-Export) |
| `gegenprobe.sh` | öffnet die festen Beispieldateien in `Tests/SiegelCoreTests/Fixtures/` und die Interop-Dateien des C#-Kerns in `windows/tests/Fixtures/` (`cs_v2_*.siegel`, auch die Windows-Hello-Art) und vergleicht mit deren README |
| `differenz.sh` | Differenztest: Mutanten der Beispieldateien vom Fuzzer (`SiegelFuzz --mutanten`), Python liest jeden selbst; keiner darf öffnen, Struktur-Urteile müssen mit Swift übereinstimmen |
| `erwartet_v1_beispiel.json` | Erwartete Werte der v1-Beispieldatei, von Hand aus `Fixtures/README.md` übernommen |
| `erwartet_v2_beispiel.json` | dasselbe für die v2-Beispieldatei (Stufe 5, mit 2FA-Geheimnis) |

## Voraussetzungen

- Python 3.12 von python.org (`/Library/Frameworks/Python.framework/Versions/3.12/bin/python3`), nur
  Standardbibliothek. Anderer Pfad: Umgebungsvariable `SIEGEL_PYTHON`.
- libsodium als dynamische Bibliothek (Homebrew: `/opt/homebrew/opt/libsodium/lib/libsodium.dylib`), über `ctypes`
  für Argon2id, XChaCha20-Poly1305, `sodium_unpad` und ChaCha20. Anderer Pfad: `SIEGEL_LIBSODIUM`.
- Keine Pakete, keine Downloads. Immer mit `-I` starten (isoliert: keine Umgebungs- und Benutzerpfade).

## Benutzen

Das Passwort kommt über die Standardeingabe, nie als Argument (sonst stünde es in der Prozessliste):

```
cd Projekte/siegel
referenz/gegenprobe.sh                                   # Beispieldateien prüfen (Exit 0 = alles stimmt)

PY=/Library/Frameworks/Python.framework/Versions/3.12/bin/python3
$PY -I referenz/siegel_referenz.py siegel Tresor.siegel --nur-kopf          # Kopf ohne Passwort
printf '%s' "$PASSWORT" | $PY -I referenz/siegel_referenz.py siegel Tresor.siegel
printf '%s' "$PASSWORT" | $PY -I referenz/siegel_referenz.py siegel Tresor.siegel --se HEX --karte HEX
printf '%s' "$EXPORTPW" | $PY -I referenz/siegel_referenz.py kdbx Siegel-Export.kdbx
```

Die Ausgabe ist JSON **mit Klartext** (Passwörter, Notizen). Nur mit Testdateien und erfundenen Einträgen benutzen,
nie mit dem echten Tresor in einem Terminal, das mitprotokolliert wird. Fehler stehen mit festem Code auf stderr
(`FEHLER wrongPassword`, `FEHLER file.checksum` …), Exit-Code 2.

## Was die Referenz prüft und kann

`.siegel` (SPEC §2, §13.1, §13.2):
- Prüfsumme `SHA3-256("Siegel vN file check" ‖ …)` zuerst, dann strenger Kopf-Leser: Magic, Version 1/2,
  `kdfAlg = 1`, KDF-Grenzen (256 MiB – 4 GiB, Vielfaches von 1 KiB, t = 3–10), v2-Faktormaske (nur Bits 0–2),
  `recoveryScheme` 1/2, Konsistenz Maske ↔ Nullfelder, FIDO-Credential 16–1024 Byte, `ctLen` 16 400 B – 64 MiB,
  keine Restbytes.
- Passwortweg: Abbildung nach RFC 8265 (Zs → Leerzeichen, NFC), Argon2id, bei v2
  `KEK_pw = HKDF-SHA512(p ‖ [e] ‖ [c] ‖ [y], kdfSalt, "Siegel v2 kek" ‖ Maske)` mit den Faktor-HKDFs aus §13.1;
  fehlender Faktor → `factorMissing.*` vor jeder Rechnung, falsche Karte → `wrongCard` (Karten-Kennung).
- pwSlot öffnen (AD `"Siegel vN slot pw" ‖ KOPF`), Inhalt öffnen (AD `"Siegel vN payload" ‖ KOPF ‖ SLOTS ‖
  generation`), Padding entfernen (Block 16 384), JSON ausgeben. Dazu Kit-Kennung, vaultID, Generation, KDF.
- Nicht enthalten: der Notfallweg (ML-KEM-1024 gibt es weder in der Python-Standardbibliothek noch in libsodium)
  und das Schreiben.

KDBX 4.x (SPEC §19):
- Signaturen, Version 4.x, Kopf-SHA-256, Kopf-HMAC (falsches Passwort), jeder Block-HMAC, Abschlussblock, keine
  Restbytes; ChaCha20 (Zähler 0), Kompression keine oder GZip, innerer Kopf, innerer ChaCha20-Strom für geschützte
  Werte in Dokumentreihenfolge; XML ohne DOCTYPE/Entities.
- Grenzen durch libsodium: nur **Argon2id** mit **16 Byte Salz** und **p = 1** (genau das, was Siegel schreibt).
  Dateien aus KeePass oder KeePassXC (meist Argon2d, 32 Byte Salz, AES) liest die Referenz darum nicht; dafür ist
  der Gegentest mit KeePassXC in `PRUEFLISTE.md` da.

## Wo sie eingesetzt wird

- `referenz/gegenprobe.sh`: v1-Beispieldatei (und `v2_beispiel.siegel`, sobald vorhanden) gegen die Werte in
  `Fixtures/README.md`, plus Manipulationsprobe (gekippte Bytes ohne und mit neu berechneter Prüfsumme, gekürzt,
  verlängert, falsches Passwort). Für v2 braucht `Fixtures/README.md` einen Abschnitt, dessen Überschrift
  `v2_beispiel.siegel` nennt, mit den Zeilen `Master-Passwort` und – je nach Faktormaske –
  `Faktor Secure Enclave (Hex)`, `Faktor Karte (Hex)`, `Faktor FIDO2 (Hex)` (Werte in Backticks).
- `Tests/SiegelCoreTests/Werkzeuge/ReferenzTests.swift`: Swift öffnet die Beispieldatei mit dem Kern, Python mit
  der Referenz, die Inhalte müssen gleich sein; Swift schreibt KeePass-Exporte, Python liest sie. Die Tests laufen
  nur, wenn Python und libsodium an den Standardorten liegen (sonst werden sie übersprungen, z. B. in der CI).

## Labels der Kit-Kennung (geklärt in SPEC v4.1)

§13.2 zählte in v4 bei den Labels, die in v2 `"Siegel v2 …"` heissen, auch `recovery checksum` und `kit id` auf,
verlangte aber im selben Satz, dass gedruckte Codes und Kits gültig bleiben. Seit v4.1 (§12, §13.2) gilt: Diese zwei
Labels gehören zum gedruckten Kit und heissen in allen Formatversionen `"Siegel v1 …"`. Die Referenz rechnet die
Kit-Kennung darum immer mit `"Siegel v1 kit id"`; `gegenprobe.sh` vergleicht sie für beide Beispieldateien.
