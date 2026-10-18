# Siegel – Spezifikation v4.8 (bindend)

Siegel ist ein nativer Passwort-Manager für macOS (SwiftUI, Apple Silicon, macOS 26+).
Keine Web-Technik, kein Server, kein Netzwerk. Diese Datei ist bindend: Code, der davon abweicht,
ist ein Fehler, oder die Spezifikation wird zuerst bewusst geändert (mit Begründung in Abschnitt 12).

**v4 (Härtestufe):** Abschnitte §13–§22 (Sicherheitsstufen, Faktoren Touch ID / QR-Karte / FIDO2, Notfallcode in
Teilen, Schutz pro Eintrag, Offline-Bericht, TOTP, KeePass-Export, Autofill vorbereitet, Prüfwerkzeuge) ergänzen
und überschreiben ältere Abschnitte, wo sie sich widersprechen (insbesondere Dateiformat v2 in §13.2, die
Schnittstelle in §22 und die Entitlements in §21).

## 0. Ziel, Bedrohungsmodell, Grenzen

Ziel: ein lokaler Tresor, der auch gegen „jetzt mitschneiden, später mit Quantenrechner entschlüsseln“
standhält, mit einer sehr ruhigen Oberfläche (weiss, schwarze Schrift).

Abgedeckt:
- **B1 Datei gestohlen** (Backup, Cloud, USB, gestohlener Laptop), auch durch einen Gegner mit
  künftigem Quantenrechner. Er bekommt nur die verschlüsselte Datei.
- **B2 Datei manipuliert**: Bitfehler, gezielte Änderungen, Parameter-Herabstufung, Vertauschen von
  Teilen zwischen Tresoren, Zurückspielen einer älteren Version (Rollback, als Warnung).
  Einschränkung: Der Notfallpfad schützt die Vertraulichkeit, nicht die Herkunft. Wer eine alte Kopie hat,
  kann eine fremde Datei bauen, die sich mit dem echten Notfallcode öffnen lässt (die öffentlichen
  Schlüssel stehen im Kopf). Darum zeigt die App nach einer Wiederherstellung Eintragszahl und letzte
  Änderung und rät, den Inhalt zu prüfen. Der Passwortpfad ist voll authentifiziert.
- **B3 Seitenkanäle im Alltag**: Bildschirmaufnahme (alle Fenster, auch Sheets), Schulterblick,
  Zwischenablage (auch ⌘C/Kontextmenü, Universal Clipboard, Clipboard-Verlauf), Textersatz/Writing Tools,
  Dienste-Menü, Bedienungshilfen-Baum, Fenster-Wiederherstellung, Absturzberichte und Unified Log,
  Klartext-CSV, Druckwarteschlange.
- **B4 Vergessene Sitzung**: automatische Sperre bei Inaktivität, Ruhezustand, Bildschirmsperre,
  Benutzerwechsel – ohne dabei Eingaben zu verlieren.
- **B5 Datenverlust** (Verfügbarkeit ist auch Sicherheit): atomares Speichern mit Rücklese-Prüfung,
  Prüfsumme gegen Bitfäule, zeitlich ausgedünnte und angeheftete Sicherungen pro Tresor, zweiter
  Sicherungsort, Notfallcode mit Fehlerkorrektur, „Zuletzt gelöscht“, nur eine laufende Instanz.

Nicht abgedeckt (ehrlich in `SICHERHEIT.md` dokumentiert): Schadsoftware, die als derselbe Benutzer
oder als root läuft, während der Tresor entsperrt ist (Keylogger, Speicher auslesen; der Sandbox-Container
schützt nicht vor Programmen desselben Benutzers; Programme mit Bedienungshilfen-Recht können bedienen);
physischer Zugriff auf den entsperrten Mac; Kopien in Time Machine/Cloud bleiben mit den damaligen Zugängen
lesbar; ohne FileVault sind Klartext-Nebenprodukte (Exporte, Druckaufträge, Ruhezustandsabbild) nicht
geschützt.

## 1. Kryptografie

Bausteine (nichts selbst erfunden):
- **libsodium 1.0.22**, statisch, vendored als `Vendor/Clibsodium.xcframework`:
  `sodium_init`, `crypto_pwhash` (Argon2id v1.3), `crypto_aead_xchacha20poly1305_ietf_*`,
  `crypto_generichash` (BLAKE2b, nur für den Master-Tag §1.6), `randombytes_buf`, `randombytes_uniform`,
  `sodium_malloc`/`sodium_free`/`sodium_mprotect_*`, `sodium_memzero`, `sodium_pad`/`sodium_unpad`,
  `sodium_memcmp`. `sodium_init()` genau einmal vor jeder Krypto (statisch in SiegelCore), Rückgabe < 0 →
  `fatalError("sodium_init")` (fester Text).
- **CryptoKit** (macOS 26): `MLKEM1024`, `Curve25519.KeyAgreement`, `SHA3_256`, `HKDF<SHA512>`.
- Kein `try!` im Kern. Alle CryptoKit-/libsodium-Fehler werden auf `SiegelError` abgebildet.

Warum das quantensicher ist (Kernaussage für die Doku): Gegen gespeicherte Daten hilft ein
Quantenrechner nur mit Grover-Suche, die symmetrische Schlüssel effektiv halbiert. Alle symmetrischen
Schlüssel sind 256 Bit (→ 128 Bit gegen Quantenangriffe). Grover hilft auch beim Passwortraten gegen
Argon2 mit 1 GiB praktisch nicht (das Orakel bräuchte ~2^33 Bit reversiblen Quantenspeicher). Der einzige
asymmetrische Teil (Notfallschlüssel) nutzt **hybrid ML-KEM-1024 (FIPS 203, Stufe 5) + X25519**: Er
bleibt sicher, solange auch nur eines der beiden Verfahren hält.

### 1.1 Master-Passwort → Schlüssel (KEK_pw)

- `pw` = UTF-8 nach RFC 8265 *OpaqueString*: zuerst jedes Zeichen der Unicode-Kategorie **Zs** ausser
  U+0020 auf U+0020 abbilden (z. B. das geschützte Leerzeichen U+00A0 von ⌥-Leertaste), dann **NFC**
  (`precomposedStringWithCanonicalMapping`). Nichts trimmen. Die Übereinstimmung von Passwort und
  Wiederholung wird nach dieser Abbildung geprüft. Bytes sofort in `SecureBytes` kopieren.
  Massgeblich ist das gemessene Verhalten von Foundation (macOS 26), auch wo es von der Unicode-Norm abweicht
  (Unicode 16 nur zum Teil, Hangul, einige Eigenheiten; v4.7). Der Windows-Kern rechnet es aus einer von Swift
  gemessenen Tabelle nach, nie über ICU (`windows/SPEC-WINDOWS.md` W12 W1.2).
- `KEK_pw = Argon2id13(pw, salt = kdfSalt[16], opslimit = t, memlimit = m, outlen = 32)`.
  `crypto_pwhash` ≠ 0 → `kdfFailed` (meist zu wenig Arbeitsspeicher), **nie** `wrongPassword`.
  `wrongPassword` nur, wenn `crypto_pwhash` 0 lieferte und das Öffnen des pwSlot scheitert.
- `kdfSalt` wird bei **jedem** Neu-Verpacken des pwSlot neu gezogen (16 B, `randombytes_buf`).
- Profile:
  - **Standard**: m = 1 GiB, t = 3 (≈1.2 s auf M5 Max, gemessen)
  - **Stark**: m = 2 GiB, t = 4 (≈3.3 s)
- Erlaubter Bereich: 256 MiB ≤ m ≤ 4 GiB, 3 ≤ t ≤ 10, m ein Vielfaches von 1 KiB. Geprüft **vor jedem
  Ableiten und vor jedem Schreiben** → `kdfParametersOutOfRange`. Gegen Herabstufung schützt die
  AD-Bindung des KOPF; die Obergrenze verhindert Speicher-/Zeit-DoS durch fremde Dateien (4 GiB, t = 10 ≈
  16 s), die Untergrenze versehentlich schwache Dateien.
- Testschalter nur unter `#if DEBUG`, nur `@testable` erreichbar: Er **verschiebt** den Bereich auf
  8 KiB ≤ m ≤ 1 MiB, 1 ≤ t ≤ 3 (weiterhin Ober- und Untergrenze), er hebt keine Prüfung auf.
- Argon2-Pfade rufen `dispatchPrecondition(condition: .notOnQueue(.main))` auf.
- Keine Versuchsgrenze, keine steigende Wartezeit, keine Selbstlöschung: Ein Offline-Angreifer kopiert die
  Datei ohnehin; Argon2 (≈1.2 s) ist die Bremse.

### 1.2 Tresorschlüssel (DEK)

- 32 Zufallsbytes (`randombytes_buf`) in `SecureBytes`. Verschlüsselt den Inhalt.
- Wird **neu erzeugt bei jedem Wechsel eines Zugangs**: Master-Passwort-Wechsel, KDF-Profil-Wechsel,
  neues Notfallkit (commitRecovery mit neuem Kit), Wiederherstellung über den Notfallcode, importBackup,
  restoreBackup. Danach werden pwSlot, recSlot und Inhalt vollständig neu verschlüsselt; der alte DEK wird
  sofort mit `sodium_free` verworfen.

### 1.3 Notfallschlüssel (hybrid post-quanten)

- `R` = 32 Zufallsbytes. Wird als Notfallcode angezeigt/gedruckt, nie gespeichert.
  256 Bit sind nötig, weil die pk-Ableitung ein schneller Offline-Prüfer ist (≈ 51–132 µs pro Kandidat).
- Ableitung (`HKDF<SHA512>.deriveKey`, `salt = vaultID`):
  - `mlkemSeed = HKDF(R, info = "Siegel v1 recovery ML-KEM-1024 seed", L = 64)`
  - `x25519Raw = HKDF(R, info = "Siegel v1 recovery X25519", L = 32)` → `Curve25519.KeyAgreement.PrivateKey(rawRepresentation:)`
  - `pkM` (1568 B, `MLKEM1024.PublicKey.rawRepresentation`) und `pkX` (32 B) stehen im Kopf.
  - **CryptoKit-Fallen**: Die Seed-Länge ist die Konstante 64 (`precondition` vor dem Aufruf; CryptoKit
    beendet bei anderer Länge den Prozess). Den Getter `seedRepresentation` nie aufrufen. 
    `MLKEM1024.PublicKey(rawRepresentation:)` akzeptiert auch ungültige Schlüssel; erst `encapsulate()` wirft.
- **Kapseln** (braucht nur die öffentlichen Schlüssel, nicht `R`), immer auf die beim Entsperren
  authentifizierten KOPF-Bytes im Speicher, nie neu von der Platte gelesen:
  - `(ssM, ctM) = pkM.encapsulate()` (ctM 1568 B, ssM 32 B)
  - Ephemerer X25519-Schlüssel `e`: `ctX = e.publicKey.rawRepresentation`,
    `ssX = e.sharedSecretFromKeyAgreement(with: pkX)` (CryptoKit wirft bei Null- und Kleinordnungspunkten).
  - `KEK_rec = SHA3-256("Siegel v1 hybrid KEM" ‖ ssM ‖ ssX ‖ ctX ‖ pkX ‖ SHA3-256(ctM) ‖ SHA3-256(pkM))`
  - Generischer Kombinierer: alle Chiffrate und öffentlichen Schlüssel beider Verfahren sind gebunden,
    damit die Sicherheit nicht von Bindungseigenschaften von ML-KEM abhängt. Labels sind ASCII ohne
    Nullbyte, alle Felder haben feste Länge und stehen in genau dieser Reihenfolge. Nicht „vereinfachen“.
  - Fehler von `encapsulate()` → `crypto("kem.encapsulate")`.
- **Entkapseln** (Wiederherstellung): Code prüfen (§1.5) → `R` → Kit-Kennung aus abgeleiteten pk
  berechnen und mit der des Tresors vergleichen; Abweichung → `wrongRecoveryCode(codeKit:vaultKit:)` →
  `MLKEM1024.PrivateKey(seedRepresentation: mlkemSeed, publicKey: MLKEM1024.PublicKey(rawRepresentation: kopf.pkM))`
  (wirft `publicKeyMismatchDuringInitialization` → ebenfalls `wrongRecoveryCode`), `pkX` vergleichen →
  `ssM = skM.decapsulate(ctM)`, `ssX = skX.sharedSecretFromKeyAgreement(with: ctX)` → `KEK_rec`.
  Nach bestandener pk-Prüfung ist **jedes** weitere Scheitern `corruptFile`, nie `wrongRecoveryCode`.
- Nutzen der Asymmetrie: Bei jeder DEK-Rotation wird der neue DEK für den Notfall-Slot neu gekapselt,
  **ohne dass die App den Notfallcode kennt**. Der gedruckte Code bleibt gültig (ausser beim bewusst neuen
  Kit).

### 1.4 AEAD

- XChaCha20-Poly1305-IETF, 24-Byte-Zufallsnonce pro Verschlüsselung, 16-Byte-Tag.
- `wrap(KEK, DEK, AD)` → `nonce[24] ‖ ct[32] ‖ tag[16]` = 72 Byte.
- Inhalt: `plaintext = sodium_pad(JSON, blocksize = 16384)` (immer ≥ 1 Byte Padding), verschlüsselt mit dem DEK.
- Kein Key-Commitment nötig: Ein-Empfänger-Tresor, alle Schlüssel stammen aus Argon2id, HKDF, SHA3 oder dem
  KEM und sind nicht vom Angreifer wählbar.

### 1.5 Notfallcode: Format, Kit-Kennung, Fehlerkorrektur, Lebenszyklus

- 32 Byte `R` ‖ 2 Byte Prüfsumme (`SHA3-256("Siegel v1 recovery checksum" ‖ R)[0..<2]`) = 272 Bit.
- Crockford-Base32 (Alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`), **MSB-first** über `R ‖ Prüfsumme`,
  55 Zeichen (275 Bit; die letzten 3 Bit sind Füllbits = 0 und müssen beim Dekodieren 0 sein, sonst
  `invalidRecoveryCodeFormat`), in 11 Gruppen à 5, getrennt mit `-`.
- Eingabe: Gross/Klein egal, alle Unicode-`White_Space`-Zeichen und `-` ignorieren, `O→0`, `I/L→1`,
  `U` ungültig, `?` = unleserliches Zeichen (höchstens 4). Falsche Länge/Zeichen →
  `invalidRecoveryCodeFormat`; Prüfsumme falsch → `recoveryCodeChecksum`.
- **Kit-Kennung** (nicht geheim) = Crockford-Base32 von `SHA3-256("Siegel v1 kit id" ‖ pkM ‖ pkX)[0..<5]`
  → 8 Zeichen, Format `XXXX-XXXX`. Steht auf dem Kit und unter Einstellungen.
- **Fehlerkorrektur** (`VaultStore.checkRecoveryCode`): Ist der Code nicht exakt gültig für diesen Tresor,
  sucht der Kern automatisch: alle Belegungen der `?`; sonst alle Varianten mit 1 oder 2 ersetzten Zeichen
  und mit vertauschten Nachbarn. Kandidat = Prüfsumme stimmt **und** abgeleitete pkM/pkX sind exakt die des
  Kopfes (kein Raten möglich: der pk-Vergleich ist endgültig). Parallel über alle Kerne
  (`DispatchQueue.concurrentPerform`), ≤ ca. 1 s. Treffer → korrigierter Code mit markierten Stellen zur
  Bestätigung.
- **Lebenszyklus**: Das Inhalts-JSON hat `recoveryConfirmedAt` (null nach `create`). Bestätigt wird durch
  Eingabe von **zwei zufällig gewählten Gruppen** (nicht per Häkchen). Ist es nach dem Entsperren null,
  zeigt die App eine nicht wegklickbare Zeile „Notfallkit nicht bestätigt – jetzt einrichten“.
  Ein neues Kit wird mit `prepareRecovery` vorbereitet (nichts geschrieben, alter Code bleibt gültig) und
  erst mit `commitRecovery` (beide Gruppen richtig) geschrieben. Ein schon abgeschriebenes Kit (z. B. nach
  „Später bestätigen“) lässt sich mit dem **ganzen** Code bestätigen (`confirmExistingRecovery`; zwei Gruppen
  lassen sich ohne gespeichertes `R` nicht prüfen). Wiederherstellen/Einspielen einer Sicherung übernimmt deren
  Kit; ist nicht belegt, dass es dasselbe Kit wie in der bisherigen Datei ist (gleiche vaultID und
  Kit-Kennung), wird `recoveryConfirmedAt` auf null gesetzt (sonst gälte ein bewusst ersetztes Kit still
  wieder, und das aktuelle Blatt passte nicht mehr).

### 1.6 Master-Passwort-Regel (im Kern erzwungen)

- `PasswordStrength.estimate` = zxcvbn-Algorithmus: kleinste Zahl Rateversuche über eine Zerlegung in
  Muster (dynamische Programmierung), `bits = log2(guesses)`. Nicht erkannte Zeichen zählen wie bei zxcvbn
  mit Kardinalität 10 je Zeichen (Brute-Force-Muster). Muster: Wörterbuch (mit Rang), umgekehrt, l33t
  (`@4→a, 3→e, 1!|→i/l, 0→o, $5→s, 7→t, 9→g`), Grossschreibung, Tastaturfolgen QWERTZ-CH und QWERTY,
  Wiederholungen (`aaaa`, `abcabc`), Folgen (`abc`, `9876`), Jahre 1900–2099, Daten (`TT.MM.JJJJ`,
  `TTMMJJ` u. ä.), Benutzereingaben.
- Gebündelte Listen (als generierte Swift-Quelldateien, Herkunft in `Sources/SiegelCore/Woerter/HERKUNFT.md`):
  häufige Passwörter (deutsch + international), deutsche und englische Wörter nach Häufigkeit, Schweizer und
  deutsche Vor- und Nachnamen, Schweizer Orte/Kantone/Vereine; `/usr/share/dict/web2` darf als Quelle für
  englische Wörter dienen (gemeinfrei). Keine Downloads beim Bauen.
- Benutzereingaben: `"siegel"`, `NSUserName()`, `NSFullUserName()` (Teile).
- **Regel** (`MasterPasswordPolicy`): `bits ≥ 60`, mindestens 12 Zeichen, höchstens 1024 UTF-8-Bytes, und jeder
  Skalar ist spätestens in **Unicode 15.0** vergeben (Eigenschaft Age; Nichtzeichen wie U+FFFE und private Zeichen
  zählen dazu; v4.7). `create`, `changeMasterPassword` und `recover` werfen sonst `passwordTooWeak` – ebenso für das
  Vernichtungs- und das Export-Passwort, die dieselbe Regel nehmen. Beim Öffnen wird nichts geprüft.
- Muss < 60 ergeben: `Passwort1234!`, `Passwort2026!`, `Sommer2026!!!`, `Qwertz123456!`, `aaaaaaaaaaaaa`,
  `Aaaaaaaaaaaa1!`, `Aralim2008!!!` (mit Benutzereingabe „aralim“), `YB-Meister-2026`.
  Muss ≥ 60 ergeben: eine generierte 6-Wort-Passphrase, 20 Zufallszeichen aus 94.
- **Passphrase vorschlagen** ist der Standardweg der Einrichtung: `PassphraseGenerator` zieht 6 Wörter per
  `randombytes_uniform` aus einer gebündelten deutschen Liste mit **genau 2048** Wörtern (4–8 Kleinbuchstaben
  a–z, keine Umlaute, eindeutig, unanstössig), getrennt mit `-` (66 Bit).
- Die Oberfläche nennt die Anzeige beim Master-Passwort „geschätzte Stärke (Bit)“, beim Generator
  „Zufalls-Entropie (Bit)“.
- **Wiederverwendung**: Während der Sitzung hält der Tresor `masterTag = crypto_generichash(key: HKDF(DEK,
  info: "Siegel v1 master tag", L = 32), pw)` in SecureBytes (nicht das Passwort). Einträge, deren `password`
  oder `history`-Wert denselben Tag ergeben, werden gemeldet (`masterPasswordReuse`) und in der Detailansicht
  als „Gleich wie Master-Passwort“ markiert. `changeMasterPassword`/`recover` lehnen ein neues Passwort ab,
  das als Eintragspasswort vorkommt (`masterPasswordReused`).

## 2. Dateiformat `.siegel` (Version 1)

Little-Endian, feste Längen, strenger Parser: falsche Länge, unbekannte Version, Restbytes → Fehler.
`vaultID` ist für die Lebensdauer des Tresors unveränderlich (HKDF-Salz für `R`, Schlüssel des
RollbackGuard, Ordner der Sicherungen).

**KOPF** (1653 Byte):

| Feld | Grösse |
|---|---|
| magic `"SIEGEL"` | 6 |
| formatVersion `u16` = 1 | 2 |
| vaultID | 16 |
| kdfAlg `u8` = 1 (Argon2id13) | 1 |
| kdfOpsLimit `u32` | 4 |
| kdfMemLimit `u64` (Byte) | 8 |
| kdfSalt | 16 |
| recoveryPKM | 1568 |
| recoveryPKX | 32 |

**SLOTS** (1744 Byte):

| Feld | Grösse |
|---|---|
| pwSlot: nonce ‖ ct ‖ tag | 72 |
| recSlot.ctM | 1568 |
| recSlot.ctX | 32 |
| recSlot: nonce ‖ ct ‖ tag | 72 |

AD der Slots: `"Siegel v1 slot pw" ‖ KOPF` bzw. `"Siegel v1 slot rec" ‖ KOPF`.

**INHALT**:

| Feld | Grösse |
|---|---|
| generation `u64` | 8 |
| nonce | 24 |
| ctLen `u32` (16 400 ≤ ctLen ≤ 64 MiB) | 4 |
| ct ‖ tag | ctLen |

AD des Inhalts: `"Siegel v1 payload" ‖ KOPF ‖ SLOTS ‖ generation`.

**PRÜFSUMME** (32 Byte, am Dateiende): `SHA3-256("Siegel v1 file check" ‖ alle Bytes davor)`.
Wird **vor** jeder Ableitung geprüft; stimmt sie nicht → `corruptFile("file.checksum")`. Nur
Fehlererkennung gegen Bitfäule, kein Schutz gegen Absicht (den leisten die AD).

Jeder Schreibvorgang schreibt `generation = max(Datei, zuletzt gesehen) + 1`.

**Formatversionen**: Jede künftige Version liest alle früheren (Parser und Testvektoren bleiben). Migriert
wird nur beim Speichern, vorher entsteht die angeheftete Sicherung `vor-migration-v1`. Eine Datei mit
höherer Version → `unsupportedVersion(n)` („Diese Datei braucht eine neuere Siegel-Version“), nie
überschreiben.

## 3. Inhalt (Klartext-JSON, nur im Speicher)

```json
{ "v": 1, "savedAt": 1792000000.0, "recoveryConfirmedAt": null,
  "entries": [ { "id": "UUID", "title": "", "username": "", "password": "", "url": "", "notes": "",
                 "created": 0.0, "modified": 0.0, "deletedAt": null,
                 "history": [ { "password": "", "changed": 0.0 } ] } ] }
```

`JSONEncoder` mit `sortedKeys`, Datum als `secondsSince1970`. Verlauf: höchstens 10 Einträge, aber
Einträge jünger als 30 Tage werden nie verdrängt (harte Obergrenze 30). Gelöschte Einträge
(`deletedAt` gesetzt) bleiben 30 Tage in „Zuletzt gelöscht“ und werden beim nächsten Speichern danach
endgültig entfernt. Grenzen je Feld: Titel/Benutzer/URL ≤ 2 KiB, Passwort ≤ 4 KiB, Notizen ≤ 256 KiB.

## 4. Speichern, Sicherungen, Rollback, Einzelinstanz

- Ort: `~/Library/Containers/com.aralim.siegel/Data/Library/Application Support/Siegel/Tresor.siegel`.
  `VaultStore.defaultDirectory()` wirft `.io("sandbox.missing")`, wenn
  `ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != "com.aralim.siegel"`.
  Tests und SiegelSnapshots übergeben immer ein Temp-Verzeichnis und einen In-Memory-RollbackGuard.
- Ordner 0700, Dateien 0600.
- **Speichern, genau in dieser Reihenfolge**: (0) Unter 64 MiB freiem Platz → `notEnoughDiskSpace`, nichts
  schreiben. (1) prüfen, dass die `generation` der Datei auf der Platte gleich der erwarteten ist, sonst
  `vaultChangedOnDisk`. (2) Temp-Datei im selben Ordner (`O_CREAT|O_EXCL`, 0600) schreiben + `F_FULLFSYNC`.
  (3) Temp neu lesen, Prüfsumme prüfen, mit dem DEK entschlüsseln, SHA-256 des Klartexts vergleichen.
  (4) bisherige Datei per `clonefile(2)` als Sicherung ablegen (scheitert bei vorhandenem Ziel, nie
  überschreiben). (5) `rename(2)`. (6) `fsync` auf den Ordner. (7) erst danach ausdünnen. Scheitert 1–4,
  bleibt die alte Datei unverändert und die Temp-Datei wird entfernt.
- **Mutationen sind transaktional**: auf einer Kopie des Inhalts ändern → speichern → erst nach Erfolg in
  den Speicherzustand übernehmen. Scheitert das Speichern, behält die Oberfläche die Eingabe.
- **Sicherungen**: `Sicherungen/<vaultID>/<UTC JJJJMMTT-hhmmss>-g<generation>-<4 Zufallshex>[-vor-<anlass>].siegel`.
  Anlässe (angeheftet): `import`, `passwortwechsel`, `notfall`, `neues-kit`, `migration`, `wiederherstellung`;
  seit v4 zusätzlich `migration-v1` und `stufenwechsel` (§13).
  Ausdünnung pro vaultID nach Zeitstempel: alles aus den letzten 48 h (max. 50), danach je die neueste pro
  Tag für 30 Tage, pro Woche für 26 Wochen, pro Monat für 24 Monate. Nie automatisch gelöscht: angeheftete
  Sicherungen, die älteste Sicherung jeder vaultID, Sicherungen fremder vaultIDs.
- **Nach Zugangswechsel** (Passwort, neues Kit) fragt die Oberfläche: „Die bisherigen Sicherungen lassen sich
  mit dem alten Passwort bzw. Notfallcode öffnen. Entfernen?“ [Entfernen] [Behalten]. `purgeBackups()` löscht
  alle Sicherungen dieser vaultID (auch angeheftete) und legt sofort eine Sicherung des aktuellen Stands an.
  Es meldet, was übrig blieb (`PurgeReport`); „Alte Sicherungen entfernt“ erscheint nur, wenn nichts übrig
  blieb. War der zweite Ort nicht erreichbar, merkt die App (vaultID, Zeit) und holt das Entfernen dort nach,
  sobald er wieder verbunden ist (`purgeSecondaryBackups`). Wurde der Zugangswechsel geschrieben, aber wegen
  Sperrens nie bestätigt, stellt die App die Frage nach dem nächsten Entsperren. Temp-Reste abgebrochener
  Schreibvorgänge (älter als 1 Minute) werden beim ersten Speichern und beim Entfernen aufgeräumt.
- **Zweiter Sicherungsort** (empfohlen): In den Einstellungen einen Ordner wählen (iCloud Drive, USB-Stick),
  gespeichert als security-scoped Bookmark (App-Ebene). Nach erfolgreichem Speichern, höchstens 1× pro
  Stunde, entsteht dort atomar `Siegel-<vaultID 8 hex>-<UTC-Zeit>.siegel`, gleiche Ausdünnung. Ohne zweiten
  Ort zeigt die Seitenleiste dezent „Keine Sicherung ausserhalb dieses Macs“ mit „Sicherung exportieren…“
  (erscheint wieder 30 Tage nach der letzten externen Sicherung). Das Bookmark wird beim Start **vor** der
  Wahl des Startbildschirms aufgelöst und erneut beim Aktivieren der App, beim Einhängen eines Datenträgers und
  vor dem Öffnen des Tresors (ohne Einhängen, `.withoutMounting`); Aushängen setzt den Ort zurück. Ist er
  gewählt, aber nicht erreichbar, zeigen die Einstellungen seinen Namen mit „Nicht verbunden“ und „Entfernen“,
  und die Seitenleiste dezent „Zweiter Sicherungsort nicht verbunden“, sobald dort Änderungen fehlen (oder nie
  bzw. vor über 30 Tagen gesichert wurde). Ergebnis jedes Versuchs: `lastSecondaryBackupResult`.
- **Verschlüsselte Sicherung exportieren**: in genau die im Sichern-Panel gewählte Datei, **ohne Nachbardatei**
  (die Sandbox gibt nur diese Datei frei); zuerst `Data.write(.atomic)`, sonst direkt in die Datei; danach
  zurücklesen und Byte für Byte vergleichen (`io("export.verify")`).
- **Tresor fehlt**: Fehlt `Tresor.siegel`, aber es gibt Sicherungen, erscheint „Tresor fehlt“ mit Liste
  (Datum, Generation) und „Wiederherstellen“. Einen neuen leeren Tresor gibt es dann nur über einen zweiten
  Knopf mit Bestätigung. Ohne Passwort oder Faktor führt „Passwort vergessen? Notfallcode verwenden“ zum Notfallweg
  über die Sicherungen; „Andere Sicherung wählen…“ nimmt eine Datei von ausserhalb (v4.4, §12).
- **Beschädigt**: Bei `corruptFile`, `kdfParametersOutOfRange` oder `unsupportedVersion` beim Entsperren
  2 s warten und einmal neu lesen. Bleibt der Fehler: „Tresordatei beschädigt“ mit „Neueste lesbare
  Sicherung öffnen“ (`restoreNewestReadableBackup`: absteigend probieren; gleiche Salz+Parameter → KEK
  wiederverwenden, kein zweites Argon2). Die beschädigte Datei wird nach
  `Sicherungen/beschaedigt-<Zeit>.siegel` verschoben, nie gelöscht. Dasselbe gibt es im **Notfallweg**
  (Passwort vergessen und Datei beschädigt): `recoverFromNewestReadableBackup` öffnet die neueste Sicherung,
  die der Code öffnet – gemessen an ihrem eigenen Kopf, nur mit derselben vaultID und demselben Kit wie die
  aktuelle Datei (ist deren Kopf unlesbar oder durch keine Sicherung bestätigt: gleiche vaultID, sonst alle).
  `recover` selbst wirft bei einem gekippten Byte weiterhin `corruptFile` (§10); der Sicherungsweg ist ein
  eigener Knopf, weil er auf einen älteren Stand zurückgeht.
- **Rollback-Stolperdraht**: Nach jedem Entsperren/Speichern `(vaultID, generation)` merken (`RollbackGuard`).
  Ist die Datei älter als zuletzt gesehen → `rollbackSuspected`, die Oberfläche fragt „Trotzdem öffnen?“.
- **Einzelinstanz** (App): `flock(LOCK_EX|LOCK_NB)` auf `Application Support/Siegel/.lock` für die Laufzeit
  des Prozesses, sonst Meldung „Siegel läuft bereits“ und Beenden.

## 5. Speicherhygiene, Prozess, Fehler und Protokolle

- `SecureBytes`: `sodium_malloc` (Guard-Pages, mlock), beim Freigeben genullt. Für DEK, KEKs, `R`,
  HKDF-Ausgaben, Master-Tag, Passwort-Bytes, entschlüsseltes JSON.
- JSON entschlüsseln in `SecureBytes`, dekodieren per `Data(bytesNoCopy:…, deallocator: .none)`, danach
  freigeben. Beim Kodieren das `Data`-Ergebnis nach dem Kopieren nullen (best effort).
- Swift-`String`s der Einträge lassen sich nicht zuverlässig nullen → beim Sperren alle Referenzen
  verwerfen; in `SICHERHEIT.md` ehrlich erwähnen.
- Start: `setrlimit(RLIMIT_CORE, 0)`. Hardened Runtime ohne `get-task-allow` (sperrt Debugger).
- **Fehler- und Protokollhygiene** (Swift schreibt Laufzeitfehler-Texte in `__crash_info` und ins Unified
  Log, gemessen):
  - In SiegelCore und SiegelUI verboten (build.sh bricht per grep ab): `try!`,
    `fatalError(`/`precondition(`/`assert(` mit String-Interpolation, `Dictionary(uniqueKeysWithValues:`,
    `print(`, `debugPrint(`, `dump(`, `NSLog(`, `privacy: .public`. `!`-Unwrap nur auf Konstanten, nie auf
    Inhaltsdaten. `Logger` nur mit Standard-Privatsphäre und nie mit Inhalten.
  - `VaultEntry`, `PasswordHistoryItem`, `UnlockedVault`, `RecoveryCode`, `PendingRecovery`, `SecureBytes`
    implementieren `CustomStringConvertible`, `CustomDebugStringConvertible` und `CustomReflectable` mit
    geschwärzter Ausgabe (z. B. `VaultEntry(id: …, redacted)`).
  - Die String-Nutzlast von `SiegelError` stammt nur aus festen Codes (`"header.length"`, `"csv.quote"`),
    nie aus Feldinhalten.

## 6. Plattform-Härtung (App)

- **App Sandbox ohne Netzwerk-Entitlement** (das System verbietet jede Verbindung). Entitlements genau:
  `com.apple.security.app-sandbox`, `com.apple.security.files.user-selected.read-write` (Import/Export),
  `com.apple.security.files.bookmarks.app-scope` (zweiter Sicherungsort), `com.apple.security.print`
  (Notfallkit).
- **Fensterschutz**: Eine zentrale `WindowGuard` setzt bei `NSApplication.didUpdateNotification`,
  `NSWindow.didBecomeKeyNotification`/`didBecomeMainNotification` **jedes** Fenster in `NSApp.windows` auf
  `sharingType = .none` (Sheets, Alerts, Settings, Panels sind eigene Fenster; vererbt sich nicht, gemessen).
  Geheimnis-Ansichten prüfen vor dem Zeichnen `window?.sharingType == .none` und zeigen sonst einen
  Platzhalter. Keine Popover für Geheimnisse (Generator ist Teil der Bearbeiten-Ansicht). Fenstertitel immer
  fest „Siegel“.
- **Externe Bildschirme**: Liegt das Fenster auf einem Bildschirm mit `CGDisplayIsBuiltin == 0` (Sidecar,
  AirPlay, Monitor), bleiben sichtbares Passwort und Notfallcode verdeckt, ebenso die Schlüsselkarte im Assistenten
  und die Kamera-Vorschau beim Scannen der Karte (sie zeigt `q`; die Erkennung läuft ohne Vorschau weiter, v4.4). Als extern gilt auch jeder
  Bildschirm in einem Spiegel-Set (`CGDisplayIsInMirrorSet != 0`, z. B. Beamer oder AirPlay mit „Spiegeln“),
  und geprüft wird jeder Bildschirm, den das Fenster schneidet (nicht nur `window.screen`). Einstellung
  „Geheimnisse auf externen Bildschirmen zeigen“, Standard aus.
- **Eingabefelder**: Klartext-Felder (Benutzername, Website, Suche, Titel) sind `HardenedTextField`
  (NSTextField-`NSViewRepresentable`). Geheimnis-Felder (Passwort beim Bearbeiten, Notizen, Verlauf,
  Notfallcode-Eingabe, Generator-Ergebnis) sind `SecretField`/`SecretTextView`. Für beide gilt in
  `becomeFirstResponder` am Field-Editor bzw. an der Textansicht: `isContinuousSpellCheckingEnabled`,
  `isGrammarCheckingEnabled`, `isAutomaticSpellingCorrectionEnabled`, `isAutomaticTextReplacementEnabled`,
  `isAutomaticQuoteSubstitutionEnabled`, `isAutomaticDashSubstitutionEnabled`,
  `isAutomaticTextCompletionEnabled`, `isAutomaticDataDetectionEnabled`, `isAutomaticLinkDetectionEnabled`
  = false, `inlinePredictionType = .no`, `writingToolsBehavior = .none`; am Feld
  `isAutomaticTextCompletionEnabled = false`. Zusätzlich bei Geheimnis-Feldern: `copy(_:)`/`cut(_:)` führen
  in `SecretPasteboard`; `validRequestor(forSendType:returnType:)` → nil (kein Dienste-Menü); Kontextmenü
  nur „Kopieren“ (beim Bearbeiten zusätzlich „Einfügen“, „Alles auswählen“); kein Ziehen. Anzeige-Texte von
  Geheimnissen sind nicht selektierbar. Master-Passwort nur in `SecureField` (NSSecureTextField, Secure Event
  Input – gemessen); ein eigenes `paste(_:)` merkt den `changeCount` und leert nach erfolgreichem Entsperren
  die Zwischenablage, wenn sie unverändert ist („Zwischenablage geleert – sie enthielt dein
  Master-Passwort“), ohne ihren Inhalt zu lesen. Die Notfallcode-Eingabe ist sichtbar (SF Mono, automatische
  Gruppierung) und aktiviert `EnableSecureEventInput()` solange sie Fokus hat (paarweise
  `DisableSecureEventInput()` auch bei Sperren und Fokusverlust).
- Beim Start `UserDefaults.standard.register(defaults: ["NSDisabledDictationMenuItem": true,
  "NSDisabledCharacterPaletteMenuItem": true])`, AutoFill-Einträge aus dem Bearbeiten-Menü entfernen.
- **Bedienungshilfen**: Geheimnis-Ansichten liefern ihren Wert an den AX-Baum nur, wenn
  `NSWorkspace.shared.isVoiceOverEnabled`; sonst `.accessibilityHidden(true)` auf dem Text und
  `accessibilityLabel("Passwort, verborgen")` am Container. Das gilt nicht nur für den Wert, sondern auch für
  die parametrisierten Text-Attribute (`AXStringForRange`, `AXAttributedStringForRange`, `AXRTFForRange`),
  `AXSelectedText`, `AXNumberOfCharacters` und `AXVisibleCharacterRange` (geprüft mit
  `skripte/ax_pruefen.swift`).
- **SecretPasteboard** (einziger Weg in die Zwischenablage): `let cc = pb.prepareForNewContents(with:
  .currentHostOnly)`, dann `setString(_, forType: .string)`, `setData(Data(), forType:
  .init("org.nspasteboard.ConcealedType"))`, `setData(Data(), forType: .init("org.nspasteboard.TransientType"))`.
  Siegel liest den Inhalt der allgemeinen Zwischenablage **nie** (nur `changeCount`). `(cc, Ablaufzeit)` in
  `UserDefaults` merken. Leeren (`clearContents()`) nach Ablauf, beim Sperren – ausser bei der Sperre durch den
  App-Wechsel (§13), die ein eben kopiertes Geheimnis bis zu seinem Ablauf stehen lässt, sonst liesse es sich nie in
  einem anderen Programm einfügen –, bei Ruhezustand, Bildschirm aus, Bildschirmsperre und Benutzerwechsel (auch ohne
  offenen Tresor), beim Beenden und beim nächsten Start (nach Absturz) – jeweils nur, wenn `changeCount == cc`.
  Solange ein Geheimnis dort liegt, verhindert eine Aktivität App Nap (der Ablauf kommt pünktlich). Die Dauer für ⌘C
  aus Geheimnis-Feldern bestimmt Siegel erst beim Kopieren: Einstellung ∧ Stufe ∧ Schutz des bearbeiteten Eintrags
  (v4.4).
- **Auto-Sperre**: Inaktivität = keine Eingabe in Siegel. `NSEvent.addLocalMonitorForEvents` (keyDown, Maus,
  Scroll) setzt eine Frist `ContinuousClock.now + n` (Standard 5 Min). Prüfung bei jedem Timer-Tick, bei
  `NSApplication.didBecomeActiveNotification` und `NSWindow.didChangeOcclusionStateNotification`, jeweils
  bevor Inhalt gezeigt wird. Zusätzlich sperren bei `NSWorkspace.willSleepNotification` (**synchron im
  Handler**, damit die sodium-Puffer vor dem Ruhezustandsabbild genullt sind), `screensDidSleepNotification`,
  `sessionDidResignActiveNotification`, DistributedNotificationCenter `com.apple.screenIsLocked`, ⌘L, Beenden.
  Scharf ist die Auto-Sperre auch ohne offenen Tresor, solange ein Bildschirm ein Zugangsgeheimnis hält
  (Notfallcode, eingetipptes Master-Passwort) oder ein Argon2-Lauf läuft; ausgenommen ist die Einrichtung.
- **Sperren ohne Datenverlust**: (a) Vor dem Verwerfen wird eine geänderte Bearbeitung per `upsert`
  gespeichert (der DEK ist noch da); ist sie ungültig, als Eintrag „Entwurf <Datum>“. Nie mit tieferem Schutz (v4.4):
  Geschützte, vernichtbare und vernichtete Einträge gehen nur über den versiegelten Weg (`setProtection`), mit dem
  gewählten Schutz, wenn seine Faktoren eingerichtet sind, sonst mit dem höchsten eingerichteten zwischen dem bisherigen
  (neu: Vorgabe) und dem gewählten – Hinweis „mit Schutz x statt y gespeichert“. Scheitert das Versiegeln, bleiben
  Titel, Benutzer und Website gespeichert, die Geheimteile sind verloren (Hinweis). Ein eigener Eintrag „Entwurf
  <Datum>“ als letzter Ausweg nur, wenn der Eintrag vorher und nachher Schutz 1 hat (mit 2FA, Hinweis). (b) Generator
  „Übernehmen“ speichert sofort (neues Passwort wird Eintragspasswort, altes wandert in den Verlauf; ein
  späteres „Abbrechen“ stellt das alte wieder her und lässt das generierte im Verlauf). (c)
  `applicationShouldTerminate` gibt `.terminateLater` zurück, bis das Speichern fertig ist (max. 5 s). Als
  Speichern zählen alle schreibenden Aufrufe (auch Zugangswechsel, Wiederherstellen, Einspielen, Exporte);
  während sie laufen, sind „Abbrechen“-Knöpfe, die das Ergebnis verwerfen würden, gesperrt.
  (d) Sperren schliesst alle Sheets, Popover und Alerts und ruft für offene NSSavePanel/NSOpenPanel
  `cancel(nil)` auf; jeder Abschluss-Handler prüft `isLocked` und tut dann nichts. Eine laufende Freigabe fragt
  danach keinen weiteren Faktor mehr ab – kein Kamera- oder Schlüssel-Sheet, kein Touch-ID-Dialog über dem
  Sperrbildschirm (v4.4, ablaeufe-4).
- **Sperren räumt auf**: DEK + Inhalt verwerfen, Wurzelansicht durch die Sperr-Ansicht ersetzen (alle
  `@State` fallen weg), Suchtext leeren. Für jedes Fenster: `makeFirstResponder(nil)`,
  `fieldEditor(false, for: nil)?.string = ""`, `undoManager?.removeAllActions()`.
- **Kein Persistieren von Inhalten**: kein `@SceneStorage`; `@AppStorage` nur für Einstellungen
  (Auto-Sperre, Ablaufzeit, externe Bildschirme, Bookmark des zweiten Sicherungsorts, Zeit der letzten
  externen Sicherung bzw. der letzten Kopie am zweiten Ort, ausstehendes Entfernen am zweiten Ort als vaultID +
  Zeit). Suche ohne Verlauf/Recents, nur über Titel, Benutzername und URL. Kein
  NSUserActivity, Handoff, CoreSpotlight, keine App Intents. Keine Fenster-Wiederherstellung
  (`.restorationBehavior(.disabled)`).
- „Website öffnen“ nur bei Schema `http`/`https` (ohne Schema wird `https://` vorangestellt), sonst
  deaktiviert. Hosts mit gemischten Schriftsystemen werden als Punycode angezeigt – geprüft pro Teil und über
  den ganzen Host samt Endung nach UTS #39 „Highly Restrictive“ (eine Schrift, oder Latein mit
  Han/Hiragana/Katakana, Han/Hangul bzw. Han/Bopomofo): `аррӏе.com` → Punycode, `пример.рф` und `日本語.jp` nicht.
- **FileVault**: Bei der Einrichtung und unter „Sicherheit“ `volumeIsEncryptedKey` des Containers prüfen;
  bei false Hinweis „FileVault ist aus: Exporte, Druckaufträge und Arbeitsspeicherabbilder sind auf diesem
  Mac nicht geschützt“ mit Knopf, der `x-apple.systempreferences:com.apple.preference.security?FileVault`
  öffnet.

## 7. Oberfläche

Strikt monochrom: Hintergrund `#FFFFFF`, Text `#000000`, Nebentext `#6E6E6E`, Haarlinien `#E5E5E5`.
Keine Farbakzente, keine Emojis (SF Symbols erlaubt, einfarbig). `NSApp.appearance = NSAppearance(named:
.aqua)` beim Start, `.containerBackground(Color.white, for: .window)`. Keine
`NavigationSplitView`/`List`-Systemauswahl: Liste als `ScrollView` + `LazyVStack` mit selbst gezeichneter
Auswahl (schwarze Fläche, weisse Schrift). `.focusEffectDisabled()` mit eigenem schwarzem Fokusrahmen.
Primärknopf als eigener `ButtonStyle` (schwarze Fläche, weisse Schrift), nicht `.borderedProminent`.
Systemschrift, Passwörter und Codes in SF Mono. Alle Texte Deutsch (Schweiz, ss). Ruhig, viel Weissraum.

Szene: `Window("Siegel", id: "main")` (kein WindowGroup), `.windowStyle(.hiddenTitleBar)`,
`.restorationBehavior(.disabled)`, `.commands { CommandGroup(replacing: .newItem) { Neuer Eintrag ⌘N } }`,
`applicationShouldTerminateAfterLastWindowClosed = true`. Fenster min. 760×480, Standard 920×600.
Einstellungen als eigene Ansicht im Hauptfenster (Sheet oder Seite, ⌘,), nur entsperrt bedienbar.

Logo: `SiegelMark` (Datei `design/SiegelMark.swift` nach `Sources/SiegelUI/` übernehmen). Sperrbildschirm
und Einrichtung: Scheibe 84 pt; Seitenleiste 21 pt; Schutzraum 5 u. Entsperren:
`withAnimation(.easeOut(duration: 0.18)) { riegel = 1 }`, dann Übergang. Falsches Passwort: `riegel`
0 → 0.15 → 0 zusammen mit kurzem Schütteln. Wortmarke „Siegel“: SF Pro Display Semibold.

Bildschirme:
1. **Einrichtung**: Logo, „Siegel“, Unterzeile „Dein Tresor. Lokal. Quantensicher verschlüsselt.“
   Standardweg „Passphrase vorschlagen“ (6 Wörter, gross in SF Mono, „Neu würfeln“), alternativ eigenes
   Passwort. Master-Passwort + Wiederholung (`SecureField`), Stärke-Anzeige (schwarzer Balken + Wort +
   geschätzte Bit). „Tresor anlegen“ erst, wenn `MasterPasswordPolicy` ok und beide gleich. FileVault-Hinweis
   falls nötig. Während Argon2: feine Fortschrittslinie. Danach **Notfallkit** (siehe 6.).
2. **Gesperrt**: Logo mittig, `SecureField`, Enter entsperrt, feine Fortschrittslinie während Argon2,
   falsch → Schütteln + „Falsches Passwort“; `kdfFailed` → „Nicht genug freier Arbeitsspeicher (1 GiB
   nötig). Andere Programme schliessen und erneut versuchen.“ Link „Notfallcode verwenden“ → Code-Eingabe
   (mit `?` für Unleserliches; Korrektur-Vorschlag mit markierten Stellen) + neues Master-Passwort ×2. Nach
   Wiederherstellung: Eintragszahl, letzte Änderung, Hinweis „Inhalt prüfen“. Bei `corruptFile`: „Neueste
   lesbare Sicherung öffnen“ – mit dem Master-Passwort und ebenso im Notfallweg mit dem Code (dann zusätzlich
   „Sicherung vom“ und Stand). Nach jeder Wiederherstellung aus einer Sicherung nennt die App deren Kit-Kennung,
   wenn das Kit nicht als bestätigt gilt. Bei `rollbackSuspected`: „Trotzdem öffnen?“. Bei `unsupportedVersion`: „Diese
   Datei braucht eine neuere Siegel-Version“.
3. **Tresor fehlt** (siehe §4).
4. **Tresor**: links Suche (⌘F) + Liste (Titel, darunter Benutzername grau), „+“ (⌘N), Schloss (⌘L), unten
   dezent „Zuletzt gelöscht (n)“ und ggf. „Keine Sicherung ausserhalb dieses Macs“ bzw. „Notfallkit nicht
   bestätigt – jetzt einrichten“. Rechts Detail: grosser Titel, Zeilen Benutzername (kopieren), Passwort
   (verdeckt, Auge, kopieren), Website (öffnen nur http/https), Notizen, aufklappbar „Frühere Passwörter (n)“
   (Datum, verdeckt, kopieren, „Verlauf leeren“ mit Bestätigung), ggf. „Gleich wie Master-Passwort“.
   Bearbeiten (⌘E), Löschen (→ Zuletzt gelöscht). Leerer Zustand ruhig. Rückmeldung „Kopiert – wird in 30 s
   gelöscht“ als dezente Zeile.
5. **Bearbeiten** mit eingebautem **Generator** (kein Popover): Länge 8–64 (Standard 24), Gross, Klein,
   Ziffern, Symbole, „Ähnliche Zeichen vermeiden“, Zufalls-Entropie in Bit, „Übernehmen“ (speichert sofort,
   siehe §6). Erstes Zeichen nie `=`, `+`, `-`, `@` (Tabellenprogramme).
6. **Notfallkit** (Einrichtung, „Neues Notfallkit…“, Banner): Code in 11 Gruppen gross (SF Mono, nicht
   selektierbar), Kit-Kennung. Zwei gleichwertige Wege: „Von Hand abschreiben“ und „Drucken…“. Text auf
   Bildschirm und Blatt: „Wer dieses Blatt und eine Kopie der Tresordatei hat, hat alle Passwörter – ohne
   Master-Passwort. Nur auf Papier aufbewahren, nicht als PDF, Foto oder in einer Cloud speichern. Nicht
   fotografieren – Live Text macht den Code in Fotos durchsuchbar.“ Drucken: Druckdialog ohne Vorschau
   (`NSPrintPanel`, Optionen ohne `.showsPreview`), danach die Geräte-URI **genau des dort gewählten Druckers**
   lesen (`PMSessionGetCurrentPrinter` + `PMPrinterCopyDeviceURI`): bei Schema ipp, http, socket, lpd, smb oder
   dnssd-Dienst `_pdl-datastream`, `_printer`, `_ipp` (ohne s) Warnung „Dieser Drucker empfängt
   unverschlüsselt über das Netzwerk; Firmendrucker speichern Aufträge oft“ mit „Trotzdem drucken“; ist keine URI
   lesbar, eine Warnung „Siegel kann nicht prüfen, wie dieser Drucker angebunden ist …“. Gedruckt wird dann ohne
   zweiten Dialog, `jobTitle = "Dokument"`. Den Code zeichnet das Blatt **nur auf Papier**
   (`jobDisposition == .spool` und `PMSessionGetDestinationType == kPMDestinationPrinter`); wählt jemand im
   Systemdialog „PDF ▾“ (Als PDF sichern, Vorschau, iCloud Drive, Mail …), steht statt des Codes „Notfallkit nur
   auf Papier – Code nicht enthalten“, und die App meldet nicht „Gedruckt“. Danach **Bestätigung**: zwei
   zufällige Gruppen eintippen. Kein Kopieren, kein PDF-Knopf.
7. **Einstellungen** (⌘,): Auto-Sperre (1/5/15/30 Min), Zwischenablage leeren (15/30/60/90 s),
   Geheimnisse auf externen Bildschirmen zeigen, Master-Passwort ändern…, KDF-Profil (Standard/Stark),
   Notfallkit (Kit-Kennung, „Notfallcode prüfen…“ – bei unbestätigtem Kit mit „Blatt als bestätigt
   markieren“ –, „Neues Notfallkit…“), Zweiter Sicherungsort…,
   Verschlüsselte Sicherung exportieren…, Sicherung einspielen…, CSV importieren…, CSV exportieren…,
   Tresor im Finder zeigen, „Sicherheit“ (kurze Erklärung der Verfahren, FileVault-Status). Heikle Aktionen
   fragen das Master-Passwort erneut ab.
8. **CSV-Import**: Vorschau (Format, Anzahl, Spalten, Konflikte, „N Einträge mit 2FA-Geheimnis (in Notizen)“),
   dann `importEntries` (nur anhängen). Danach: „Quelldatei jetzt endgültig löschen?“ (`FileManager.removeItem`
   auf die URL aus dem NSOpenPanel, nicht in den Papierkorb) mit Hinweis auf Spotlight-, Vorschau- und
   SSD-Reste.
9. **CSV-Export** (Master-Passwort): Warnung (Spotlight, Vorschaubilder, Time Machine, SSD-Reste, „Nicht mit
   Excel/Numbers öffnen oder speichern – Passwörter können verändert werden“, Verlauf wird nicht exportiert).
   Bei unverschlüsseltem Volume zweite Bestätigung. Nach dem Export bleibt die Zeile „Exportdatei endgültig
   löschen“ stehen, bis erledigt oder weggeklickt.

## 8. Module und Schnittstelle (bindend für die Oberfläche)

Paket `Projekte/siegel/Package.swift` (**swift-tools-version:6.2**, `platforms: [.macOS(.v26)]`):
- `Clibsodium` – binaryTarget `Vendor/Clibsodium.xcframework` (erzeugt von `skripte/libsodium_holen.sh`)
- `SiegelCore` – Bibliothek, keine UI. Abhängig von Clibsodium, CryptoKit.
- `SiegelUI` – Bibliothek mit allen SwiftUI-Ansichten und dem App-Modell.
- `Siegel` – ausführbares Ziel, nur `@main`.
- `SiegelSnapshots` – ausführbares Ziel, rendert Bildschirme offscreen als PNG:
  `_ = NSApplication.shared`, `setActivationPolicy(.prohibited)`, Ansicht in `NSHostingView` in einem
  randlosen Offscreen-`NSWindow` (Appearance `.aqua`), `layoutSubtreeIfNeeded()`,
  `bitmapImageRepForCachingDisplay` + `cacheDisplay(in:to:)`. Kein `ImageRenderer`. Nur Demodaten
  (erfundene Einträge), Temp-Ordner, In-Memory-RollbackGuard.
- `SiegelCoreTests` – swift-testing.

Öffentliche API von `SiegelCore` (Signaturen bindend, Interna frei; alle Typen `Sendable`):

```swift
public enum SiegelError: Error, Equatable, Sendable {
    case wrongPassword
    case wrongRecoveryCode(codeKit: String, vaultKit: String)
    case invalidRecoveryCodeFormat
    case recoveryCodeChecksum
    case recoveryConfirmationMismatch
    case passwordTooWeak(bits: Double)
    case masterPasswordReused
    case corruptFile(String)                 // nur feste Codes
    case unsupportedVersion(UInt16)
    case kdfParametersOutOfRange
    case kdfFailed
    case vaultAlreadyExists
    case vaultMissing
    case vaultChangedOnDisk
    case notEnoughDiskSpace
    case csvInvalid(line: Int, reason: String) // reason nur aus fester Code-Liste
    case exportLocationRejected(String)      // "icloud"
    case io(String)                          // nur feste Codes
    case crypto(String)                      // nur feste Codes
}

public struct KDFParameters: Equatable, Sendable {
    public let opsLimit: UInt32
    public let memLimitBytes: UInt64
    public init(opsLimit: UInt32, memLimitBytes: UInt64)
    public static let standard: KDFParameters   // 1 GiB, t=3
    public static let strong: KDFParameters     // 2 GiB, t=4
}

public struct PasswordHistoryItem: Codable, Equatable, Hashable, Sendable {
    public var password: String; public var changed: Date
    public init(password: String, changed: Date)
}

public struct VaultEntry: Codable, Identifiable, Equatable, Hashable, Sendable {
    public var id: UUID
    public var title, username, password, url, notes: String
    public var created, modified: Date
    public var deletedAt: Date?
    public var history: [PasswordHistoryItem]
    public init(title: String = "", username: String = "", password: String = "",
                url: String = "", notes: String = "")
}

public struct RecoveryCode: Sendable {           // nie gespeichert
    public let formatted: String                  // "XXXXX-XXXXX-…" (11 Gruppen)
    public let kitID: String                      // "XXXX-XXXX"
    public var groups: [String] { get }
}

public struct PendingRecovery: Sendable {        // nichts geschrieben (ausser bei create, dort schon gültig)
    public let code: RecoveryCode
    public let confirmationGroups: [Int]          // zwei verschiedene Gruppenindizes 0…10, zufällig
}

public enum RecoveryCodeMatch: Sendable, Equatable {
    case exact
    case corrected(formatted: String, changedPositions: [Int])   // Positionen im 55-Zeichen-Code
}

public struct BackupInfo: Sendable, Equatable, Identifiable {
    public var id: URL { url }
    public let url: URL
    public let date: Date
    public let generation: UInt64
    public let vaultID: UUID?                     // aus dem Kopf gelesen; nil = unlesbar
    public let reason: String?                    // Anlass bei angehefteten Sicherungen
    public let isExternal: Bool
}

public struct PurgeReport: Sendable, Equatable {      // v3.1
    public var removed = 0, failed = 0
    public var secondaryUnreachable = false
    public var interrupted = false                    // v4.4: Entfernen brach ab (nach gültigem Speichern)
    public var isComplete: Bool { get }
}

public enum SecondaryBackupResult: Sendable, Equatable { // v3.1
    case written(Date), notDue, unreachable, failed
}

public struct ImportReport: Sendable, Equatable {
    public var added = 0, skippedDuplicates = 0, conflicts = 0
    public var withOTPSecret = 0, movedToNotes = 0
    public var passwordsWithControlCharacters = 0, apostrophePrefixed = 0
}

public struct CSVImportResult: Sendable {
    public enum Format: String, Sendable { case applePasswords, chrome, firefox, bitwarden }
    public let format: Format
    public let entries: [VaultEntry]
    public let report: ImportReport               // vorläufig (Dubletten erst bei importEntries)
}

public enum UnlockOutcome: Sendable {
    case unlocked(UnlockedVault)
    case rollbackSuspected(UnlockedVault, seenGeneration: UInt64, fileGeneration: UInt64)
}

public protocol RollbackGuard: Sendable {
    func lastSeenGeneration(vaultID: UUID) -> UInt64?
    func record(vaultID: UUID, generation: UInt64)
}
public final class UserDefaultsRollbackGuard: RollbackGuard, @unchecked Sendable {
    public init(defaults: UserDefaults = .standard)
}
public final class InMemoryRollbackGuard: RollbackGuard, @unchecked Sendable { public init() }

public final class VaultStore: @unchecked Sendable {
    public init(directory: URL, rollbackGuard: RollbackGuard)
    public static func defaultDirectory() throws -> URL          // nur im Sandbox-Container
    public static func volumeIsEncrypted(_ url: URL) -> Bool?
    public var vaultURL: URL { get }
    public var vaultExists: Bool { get }
    public var secondaryBackupDirectory: URL? { get set }        // App löst das Bookmark auf und startet den Zugriff
    public func create(masterPassword: String, kdf: KDFParameters = .standard) throws -> (UnlockedVault, PendingRecovery)
    public func unlock(masterPassword: String) throws -> UnlockOutcome
    public func checkRecoveryCode(_ input: String) throws -> RecoveryCodeMatch   // inkl. Korrektur; liest nur den Kopf
    public func recover(code: String, newMasterPassword: String, kdf: KDFParameters = .standard) throws -> UnlockedVault
    public func checkRecoveryCodeAgainstBackups(_ input: String) throws -> RecoveryCodeMatch            // v3.1, §4
    public func recoverFromNewestReadableBackup(code: String, newMasterPassword: String,
                                                kdf: KDFParameters = .standard) throws -> (UnlockedVault, BackupInfo)  // v3.1
    public func backups() -> [BackupInfo]                        // alle, neueste zuerst
    public func restoreBackup(_ backup: BackupInfo, masterPassword: String) throws -> UnlockedVault
    public func restoreNewestReadableBackup(masterPassword: String) throws -> (UnlockedVault, BackupInfo)
    public func quarantineCorruptVault() throws -> URL
    public func importBackup(from url: URL, masterPassword: String) throws -> UnlockedVault
    public func exportBackup(to url: URL) throws                 // verschlüsselte Kopie, ohne Nachbardatei, zurückgelesen
    public var lastSecondaryBackupResult: SecondaryBackupResult? { get }                   // v3.1
    public func purgeSecondaryBackups(vaultID: UUID, before: Date) -> PurgeReport          // v3.1, nachholen
    public static func passwordsMatch(_ a: String, _ b: String) -> Bool                   // Abbildung wie §1.1
}

public final class UnlockedVault: @unchecked Sendable {          // threadsicher (interner Lock)
    public var vaultID: UUID { get }
    public var generation: UInt64 { get }
    public var kdf: KDFParameters { get }
    public var kitID: String { get }
    public var recoveryConfirmed: Bool { get }
    public var entries: [VaultEntry] { get }                     // ohne gelöschte
    public var deletedEntries: [VaultEntry] { get }
    public var lastModified: Date? { get }
    public var masterPasswordReuse: Set<UUID> { get }
    public func upsert(_ entry: VaultEntry) throws               // transaktional; setzt modified, pflegt history
    public func delete(id: UUID) throws                          // setzt deletedAt
    public func restore(id: UUID) throws
    public func purgeDeleted(id: UUID) throws                    // endgültig
    public func clearHistory(id: UUID) throws
    public func importEntries(_ entries: [VaultEntry]) throws -> ImportReport   // nur anhängen, vorher Sicherung „vor-import“
    public func exportCSV(toParent directory: URL, masterPassword: String) throws -> URL   // .noindex-Ordner, siehe §7.9
    public func verify(masterPassword: String) -> Bool           // Argon2, nicht Main-Thread
    public func changeMasterPassword(current: String, new: String, kdf: KDFParameters? = nil) throws
    public func prepareRecovery(masterPassword: String) throws -> PendingRecovery
    public func commitRecovery(_ pending: PendingRecovery, confirmation: [String]) throws
    public func confirmExistingRecovery(code: String) throws    // v3.1: ganzer Code bestätigt das bestehende Kit
    @discardableResult public func purgeBackups() throws -> PurgeReport   // v3.1: Bericht
    public func lock()                                           // DEK + Inhalt verwerfen, danach unbrauchbar
    public var isLocked: Bool { get }
}

public enum PasswordGenerator {
    public struct Options: Equatable, Sendable {
        public var length: Int = 24
        public var uppercase = true, lowercase = true, digits = true, symbols = true
        public var avoidAmbiguous = false
        public init()
    }
    public static func generate(_ options: Options) -> String  // randombytes_uniform, je gewählte Klasse ≥1, erstes Zeichen nie = + - @
    public static func entropyBits(_ options: Options) -> Double
}

public enum PassphraseGenerator {
    public static let wordListCount: Int                       // 2048
    public static func generate(words: Int = 6) -> String      // "wort-wort-…"
    public static func entropyBits(words: Int) -> Double
}

public enum PasswordStrength {
    public enum Level: Int, Sendable { case veryWeak, weak, fair, strong, veryStrong }
    public static func estimate(_ password: String, userInputs: [String] = []) -> (bits: Double, level: Level)
}

public enum MasterPasswordPolicy {
    public static let minimumBits: Double       // 60
    public static let minimumLength: Int        // 12
    public static let maximumUTF8Bytes: Int     // 1024
    public static func check(_ password: String) -> (bits: Double, ok: Bool)   // userInputs: "siegel", NSUserName(), NSFullUserName()
}

public enum CSVImport {
    public static func parse(_ data: Data) throws -> CSVImportResult
}
public enum CSVExport {
    public static func export(_ entries: [VaultEntry]) -> Data     // name,url,username,password,note; alle Felder in Anführungszeichen
}
```

Schwere Aufrufe (Argon2, Code-Korrektur) laufen nie auf dem Main-Thread; die UI ruft sie über
`Task.detached(priority: .userInitiated)` auf.

**CSV-Details**: Spalten fest. Apple: `Title,URL,Username,Password,Notes,OTPAuth`. Chrome:
`name,url,username,password,note`. Firefox: `url,username,password,httpRealm,formActionOrigin,guid,
timeCreated,timeLastUsed,timePasswordChanged` (ms → created/modified). Bitwarden: `folder,favorite,type,name,
notes,fields,reprompt,login_uri,login_username,login_password,login_totp` (type=note → nur Notizen). Jede
nicht abgebildete, nicht leere Spalte kommt als Zeile „Spalte: Wert“ in `notes`; Spaltennamen über 256 Byte UTF-8
(ohne Leerraum am Rand) haben keine Rolle und zählen nicht als Doppel (v4.8). RFC 4180 (Anführungszeichen,
Kommas, Zeilenumbrüche in Feldern, BOM). Grenzen: Datei ≤ 16 MiB, ≤ 20 000 Zeilen, Feldgrenzen §3; Verstoss →
`csvInvalid(line:reason:)`, kein Teilimport. Aus Titel, Benutzer, URL werden U+0000–001F, U+007F,
U+200E/200F, U+202A–202E, U+2066–2069 entfernt; Passwörter bleiben byte-genau (Report zählt Steuerzeichen und
führende `'`). Dubletten in `importEntries`: gleicher Host (klein, IDNA) + Benutzer + Passwort → übersprungen;
gleicher Host + Benutzer mit anderem Passwort → neuer Eintrag mit Titelzusatz „(Import)“, Bestand wird nie
geändert. Kein `Dictionary(uniqueKeysWithValues:)`.
**CSV-Export-Hygiene** (`exportCSV`): Master-Passwort prüfen; Ziel in iCloud Drive (`isUbiquitousItemKey`) →
`exportLocationRejected("icloud")`; im Ziel entsteht `Siegel-Export-<JJJJ-MM-TT>.noindex/` (0700, Spotlight
ignoriert `.noindex`) mit `Siegel-Export.csv` (0600); `isExcludedFromBackup = true` für Ordner und Datei.

## 9. Bau

- `skripte/libsodium_holen.sh`: Homebrew-`libsodium.a` + Header → `Vendor/Clibsodium.xcframework`,
  `module.modulemap` = `module Clibsodium { header "sodium.h" export * }` (ohne `link`). Abbruch, wenn
  `SODIUM_VERSION_STRING` ≠ 1.0.22. Schreibt `Vendor/LIBSODIUM.txt` (Version, SHA-256).
- `skripte/icon_bauen.sh`: `design/icon-ebene.svg` (um 1024/824 vergrössert, siehe `design/LOGO.md`) →
  `build/Siegel.icon/Assets/logo.svg`, dazu `icon.json` mit weisser Füllung, Gruppe ohne Schatten
  (`"shadow": {"kind": "none"}`), `"specular": false`, Transluzenz aus, `supported-platforms` macOS. Dann
  `xcrun actool build/Siegel.icon --compile <App>/Contents/Resources --platform macosx
  --minimum-deployment-target 26.0 --app-icon Siegel --output-partial-info-plist build/icon.plist
  --target-device mac` → `Assets.car` + `Siegel.icns`. Info.plist: `CFBundleIconName = Siegel`,
  `CFBundleIconFile = Siegel`. Prüfung per `NSWorkspace.shared.icon(forFile:)` (kein grauer Rahmen).
- `build.sh`: `export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`; zuerst die Grep-Sperren aus
  §5 (Abbruch mit Datei:Zeile); `swift build -c release`, Binärpfad über `--show-bin-path`; schnürt
  `~/Applications/Siegel.app` (Bundle-ID `com.aralim.siegel`, `LSMinimumSystemVersion` 26.0,
  `LSApplicationCategoryType` public.app-category.utilities, `NSHumanReadableCopyright`), Entitlements aus
  `skripte/Siegel.entitlements` (genau §6), Signatur ad-hoc:
  `codesign --force --options runtime --timestamp=none --entitlements skripte/Siegel.entitlements --sign - Siegel.app`.
  Danach prüft build.sh und bricht sonst ab: `codesign --verify --strict` ok; Entitlements enthalten genau die
  vier aus §6 und kein `get-task-allow`; Flags zeigen `adhoc,runtime`; `otool -L` zeigt weder `sodium` noch
  `/opt/homebrew`. Eine laufende Siegel-Instanz wird vorher sauber beendet (nicht `kill -9`). `./build.sh run`
  startet danach.

## 10. Tests (müssen grün sein)

- Anlegen/Entsperren/Speichern-Rundlauf; falsches Passwort; `kdfFailed` ≠ `wrongPassword`.
- **Jedes einzelne Byte** der Datei kippen → `corruptFile` (Prüfsumme). Zusätzlich: Byte kippen **und
  Prüfsumme neu berechnen** (Angreifer) → für **beide** Wege (Passwort und Notfallcode) nie Erfolg, nie
  falscher Inhalt, nie Absturz. Abgeschnittene/verlängerte Datei → `corruptFile`.
- KDF-Grenzen beim Lesen und beim Schreiben.
- Notfallcode: Rundlauf, Prüfsumme, Füllbits ≠ 0, fremder Tresor (`wrongRecoveryCode` mit Kit-Kennungen),
  Leerraum/Bindestriche/O/I/L; Korrektur: 1 und 2 ersetzte Zeichen, vertauschte Nachbarn, 4 `?` →
  `corrected` mit richtigen Positionen; zufälliger Code → kein Treffer.
- Lebenszyklus: `create` → `recoveryConfirmed == false`; `commitRecovery` mit falschen Gruppen →
  `recoveryConfirmationMismatch` und nichts geschrieben; `prepareRecovery` ohne commit lässt alten Code gültig.
- Passwortwechsel rotiert DEK und KDF-Salz, der Notfallcode bleibt gültig. Altes Passwort öffnet die neue
  Datei nicht; der DEK aus einer alten Datei entschlüsselt den neuen Inhalt nicht. Neues Kit macht alten Code
  ungültig; DEK aus altem recSlot entschlüsselt den neuen Inhalt nicht.
- Generation steigt bei jedem Schreibweg; Rollback-Erkennung; `vaultChangedOnDisk`; Speichern bei
  scheiternder Rücklese-Prüfung lässt die alte Datei unverändert; Sicherungsnamen kollidieren nie (gleiche
  Generation zweimal); Ausdünnung behält angeheftete und älteste; Wiederherstellung einer alten Generation
  löscht keine neueren Sicherungen.
- Beschädigt: `restoreNewestReadableBackup` überspringt kaputte Sicherungen; `quarantineCorruptVault`
  verschiebt. Notfallweg bei beschädigter Datei (Inhalt bzw. Kopf gekippt) über die neueste passende
  Sicherung; fremder Tresor und älteres Kit werden nie angenommen.
- Wiederherstellen/Einspielen von vor einem Kit-Wechsel → `recoveryConfirmed == false`; gleiches Kit bleibt
  bestätigt; `confirmExistingRecovery` nur mit dem ganzen, passenden Code.
- Export ohne Nachbardatei (Ordner schreibgeschützt, Datei beschreibbar); `purgeBackups` meldet einen nicht
  lesbaren zweiten Ort; Temp-Reste werden aufgeräumt.
- Policy/Stärke: alle Beispiele aus §1.6; `create`/`changeMasterPassword`/`recover` werfen `passwordTooWeak`;
  Wiederverwendung (`masterPasswordReuse`, `masterPasswordReused`).
- Normalisierung: `"a\u{00A0}b"` ≡ `"a b"`, `"e\u{0301}"` ≡ `"é"`.
- X25519 mit Nullpunkt wirft (CryptoKit), Seed-Länge-Precondition dokumentiert.
- **Feste Testvektoren** in `Tests/SiegelCoreTests/Fixtures/`, nie ändern:
  (a) `R = 00 01 … 1f`, `vaultID = a0 a1 … af` →
  `SHA3-256(pkM) = 07d2a982d901e86a75c81c97704b1a66571c8ae4664039ec55e286cbbac206f2`,
  `pkX = 157638f533039b946e64edc0135d67ad5c805d89cc0530bec075e14266213107`,
  Code = `000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FRAC8`;
  (b) Beispieldatei `v1_beispiel.siegel` mit m = 256 MiB, t = 3 und bekanntem Passwort und Code (in
  `Fixtures/README.md`); muss sich in jeder künftigen Version über beide Wege öffnen lassen; (c) `KEK_rec` für
  die fixierten (ctM, ctX) dieser Datei.
- Generator (Länge, Klassen, erstes Zeichen, grobe Gleichverteilung), Passphrase (Liste genau 2048, eindeutig,
  nur a–z, 4–8 Zeichen); CSV (RFC 4180, BOM, alle vier Formate, Grenzen, Steuerzeichen, Dubletten, Notizen-
  Übernahme, OTP-Zählung); CSV-Export (alle Felder zitiert, `.noindex`, Rechte, iCloud-Ablehnung).
- Geschwärzte Beschreibungen: `String(describing:)`, `debugDescription` und `dump` von `VaultEntry` und
  `RecoveryCode` enthalten kein Geheimnis.
- Padding verschleiert kleine Grössenunterschiede.
- Tests mit echten Profilen (≥ 256 MiB) sind `.serialized`; die übrigen nutzen den Testschalter.
- Manuell (in `PRUEFLISTE.md`): CGWindowList zeigt für alle eigenen Fenster `kCGWindowSharingState == 0`,
  auch mit Sheet; ⌘C aus Geheimnis-Feldern erscheint nicht im Zwischenablageverlauf; Sidecar verdeckt.

## 11. Dateien

`SPEC.md` (diese Datei), `SICHERHEIT.md` (Bedrohungsmodell, Verfahren, Kostentabelle für Offline-Angriffe,
ehrliche Grenzen für Laien, FileVault-Empfehlung, Absturzberichte/„Analysedaten teilen“, Druckwarteschlange,
Bedienungshilfen), `LIESMICH.md` (Bauen, Starten nur über `./build.sh run`, Speicherort, Bedienen),
`PRUEFLISTE.md` (manuelle Prüfungen), `design/` (Logo, Icon, Konzept, Wettbewerb).

## 12. Änderungsprotokoll und verworfene Varianten

- v1 (16.10.2026): Erstfassung.
- v2 (16.10.2026): Nach Krypto- und Plattform-Review: DEK-Rotation bei jedem Zugangswechsel; neues
  KDF-Salz bei jedem Neu-Verpacken; Datei-Prüfsumme; Kit-Kennung; RFC-8265-Abbildung; Base32 MSB-first mit
  Füllbits; CryptoKit-Fallen; Grenzen auch beim Schreiben; Testvektoren; gehärtete Textfelder;
  Zwischenablage-Ablauf; Szene/Einzelinstanz; Icon über Icon Composer; ad-hoc-Signatur mit Prüfung;
  swift-tools 6.2.
- v3 (16.10.2026): Nach Angreifer-Review: zxcvbn-Schätzung + im Kern erzwungene Passwort-Regel +
  Passphrase; Notfallkit-Lebenszyklus mit Gruppen-Bestätigung, Prüfen und Fehlerkorrektur; Speichern mit
  Rücklese-Prüfung, clonefile-Sicherungen pro vaultID mit Zeit-Ausdünnung und Anheften, zweiter
  Sicherungsort, „Tresor fehlt“, „Beschädigt“-Weg, `kdfFailed`; „Zuletzt gelöscht“; Sperren ohne
  Datenverlust; Fensterschutz für alle Fenster; Geheimnis-Felder mit eigener Zwischenablage, ohne Dienste und
  AX-Werte; Fehler-/Protokollhygiene mit Grep-Sperren; CSV-Semantik (nur anhängen) und -Hygiene;
  Druckerwarnung; FileVault-Hinweis; externe Bildschirme; Master-Passwort-Wiederverwendung; Formatversionen.
- v3.1 (16.10.2026): Nach dem Prüfbericht (Befunde #1–#17): AX-Sperre auch für parametrisierte
  Text-Attribute; Sicherung exportieren ohne Nachbardatei (Sandbox) mit Rücklese-Prüfung; Wiederherstellen setzt
  die Kit-Bestätigung zurück, wenn das Kit nicht belegt gleich ist; Notfallweg bei beschädigter Datei über die
  Sicherungen (`checkRecoveryCodeAgainstBackups`, `recoverFromNewestReadableBackup`); Auto-Sperre auch bei
  offenen Zugangsgeheimnissen ausserhalb des Tresors; Spiegeln und Fenster über zwei Bildschirme gelten als
  extern; Notfallkit-Code nur auf Papier, Druckerprüfung nach dem Dialog am gewählten Drucker, Warnung auch ohne
  lesbare URI; zweiter Sicherungsort wird vor der Startroute und bei Einhängen/Aktivieren neu aufgelöst, mit
  Status (`lastSecondaryBackupResult`) und Anzeige „nicht verbunden“; `purgeBackups` mit Bericht und
  nachgeholtem Entfernen am zweiten Ort; schreibende Hintergrundaufrufe zählen als Speichern (Beenden wartet,
  Abbrechen gesperrt), offene Purge-Frage nach Sperren; Homographen über den ganzen Host;
  `confirmExistingRecovery` für ein schon abgeschriebenes Kit; Passwort-Schätzung erkennt Trennstücke aus
  0–3 beliebigen Nicht-Buchstaben (auch je Lücke verschieden) und l33t in Passphrasen-Ketten
  (`Staerke/Woerter/HERKUNFT.md`). Die öffentliche Schnittstelle in §8 wächst entsprechend; `purgeBackups`
  gibt jetzt einen Bericht zurück.
- v4 (17.10.2026): Härtestufe nach Wunsch des Nutzers: fünf Tresor-Stufen (§13) mit kryptografisch echten
  Faktoren (Secure Enclave/Touch ID, QR-Schlüsselkarte über die Kamera, FIDO2-Sicherheitsschlüssel über
  hmac-secret, §14), Notfallcode als Shamir 2 aus 3 (§15), Schutz 1–5 pro Eintrag mit eigener Versiegelung
  (§16), Offline-Sicherheitsbericht (§17), TOTP (§18), KeePass-Export KDBX 4.1 (§19), Autofill vorbereitet –
  das kostenlose Apple-Konto bekommt das Entitlement nicht (gemessen, §20) –, Fuzzer, Sanitizer-Läufe,
  Python-Referenz, Signatur-Selbstprüfung, CI (§21). Dateiformat v2, v1 bleibt lesbar.
- v4.1 (17.10.2026): Nach der Integration der Härtestufe bewusst anders gelöst (geht den Abschnitten §13–§22 vor):
  - §13.2: `recovery checksum` und `kit id` heissen in allen Formatversionen `"Siegel v1 …"` (gehören zum gedruckten
    Kit; mit v2-Labels wären v1-Codes nach der Umstellung ungültig). Das Notfall-Schema im KOPF beschreibt das Kit,
    nicht die Stufe: Nach `recover(shares:)` gilt Stufe 1 mit dem Kit „2 aus 3“, bis ein neues Kit geschrieben wird;
    ein Stufenwechsel mit anderem Schema verlangt ein neues Kit (sonst `notAllowedAtLevel`). Neue Anlässe der
    angehefteten Sicherungen: `migration-v1` (bytegleiche v1-Datei vor dem ersten v2-Schreiben, auch wenn der Anlass
    ein Passwortwechsel ist) und `stufenwechsel`. Die KDF-Tabelle in §13 gilt beim Stufenwechsel; Lesen nimmt jedes
    KDF in den Grenzen an, `changeMasterPassword(kdf:)` lehnt in Stufe 3–5 ein schwächeres Profil ab.
  - §13/§16: Prüfwert `check = HKDF(FIDO-Ausgabe, vaultID, "Siegel v2 fido check", 16)` im Inhalt, damit ein nur für
    Einträge eingerichteter Sicherheitsschlüssel ohne Neuregistrierung in Stufe 5 übernommen wird
    (`UnlockedVault.securityKeyCredential`). Eintrags-Faktoren, an denen versiegelte Einträge hängen, lassen sich nicht
    ersetzen (`notAllowedAtLevel`). `restoreNewestReadableBackup(…factors:)` hört bei fehlendem Faktor bzw. anderer
    Karte der neuesten Sicherung mit `factorMissing`/`wrongCard` auf, statt still einen älteren Stand einzusetzen.
  - §14.1: Schlüsseldatei `<keyID>.siegelhw` = magic `SIEGELHW`, Version, kind (Entsperren/Einträge), keyID, Blob,
    Punkt, SHA3-Prüfsumme. „Finger nicht erkannt“ → `factorCancelled`; Sperre, nicht eingerichtet, Unbekanntes →
    `factorUnavailable` (Sperre und unerreichbarer Sensor ab v4.4 vorübergehend, §12). `isAvailable` verlangt eingerichtetes Touch ID. Einrichten zeigt feste Texte (kein
    reason-Parameter). §14.2: der Scanner liefert nur Inhalte mit Präfix `SIEGELKARTE` (≤ 256 Zeichen).
    §14.3: Geräte, die für makeCredential eine PIN/UV verlangen (ohne `makeCredUvNotRqd`), `alwaysUv` oder ein
    UV-Flag liefern, werden vor der Berührung mit `factorUnavailable(.securityKey)` abgelehnt; Attestation und
    Assertion-Signatur werden nicht geprüft (falsche Ausgabe ergibt einen falschen Schlüssel).
  - §15: 35 Byte = 56 Zeichen ohne Füllbits; die 12. Gruppe hat 1 Zeichen, Bestätigungsgruppen kommen nur aus den 11
    vollen. Bei `.shamir2of3` ist `PendingRecovery.code.formatted` leer und `confirmationGroups` leer (nie ein ganzer
    Code). Zusätzlich öffentlich: `checkRecoverySharesAgainstBackups`, `recoverFromNewestReadableBackup(shares:)`,
    `confirmExistingRecovery(shares:)`, `recoveryCodeInputIsComplete`, `recoveryShareInputIsComplete`,
    `recoveryShareIndex`.
  - §16.1: K und reuseTag hängen an einem stabilen 32-Byte-Grundschlüssel `entryKey` (EBK) im verschlüsselten Inhalt
    statt am DEK (der DEK rotiert bei jedem Zugangswechsel): `base = HKDF(EBK, salt = entryID, "Siegel v2 entry dek")`.
    Der Notfall-Umschlag geht nicht direkt an pkM/pkX, sondern an eine **Notfall-Gruppe pro Faktormaske** (Gruppen-
    geheimnis hybrid an das Kit gekapselt, zusätzlich als Anker unter den Faktoren der Maske versiegelt); ein neues Kit
    braucht so eine Freigabe pro Gruppe statt pro Eintrag. Dafür async-Varianten (`@concurrent`, mit
    `entryFactors: EntryFactorProvider?`) von `commitRecovery`, `changeSecurityLevel`, `exportCSV`, `exportKeePass`;
    die synchronen Signaturen aus §22 werfen `factorMissing`, sobald versiegelte Einträge eine Freigabe brauchen.
    `upsert` ändert bei versiegelten Einträgen nur offene Felder (`io("entry.sealedSecrets"/"entry.protection"/
    "entry.stale")`), Geheimteile nur über `setProtection` (dazu `EntrySecrets.replacingPassword(with:)`).
    Ehrliche Grenze dazu (SICHERHEIT.md): Wer den entsperrten Mac übernommen hat, bekommt mit einer getauschten Freigabe
    für einen Anker alle Einträge dieser Maske.
  - §17: „Gleich wie Master“ wird nicht gespeichert, sondern über den reuseTag des Master-Passworts gerechnet.
  - §18/§19/§22: `TOTP.Parameters` mit werfendem Init und `secretByteCount` (Geheimnis nur in SecureBytes), 12 feste
    Codes `totpInvalid("totp.*")`; `VaultEntry.totp` ≤ 4 KiB im Kern, `TOTP.parse` ≤ 2 KiB. KDBX-Argon2 mit 16 Byte
    Salz (libsodium; KeePass ≥ 8, KeePassXC 8–32). Export-Passwort gleich dem Master-Passwort → `masterPasswordReused`.
  - §8: CSV höchstens 256 Spalten, Datensätze höchstens so breit wie die Kopfzeile (`csv.header.unknown`/
    `csv.fieldCount`, geprüft während des Lesens).
  - §22: `LevelPolicy` hat (eingefroren in `Faktoren.swift`) `defaultEntryProtection` statt `perEntryRelease`.
  - Offen: `SiegelFuzz`/`skripte/fuzz.sh` (§21) fehlen noch; AddressSanitizer scheitert am Linker der Werkzeugkette
    (`ld`-Assertion beim Bau von SiegelCore.o), ThreadSanitizer läuft. (Erledigt in v4.2.)
- v4.2 (17.10.2026): Prüfwerkzeuge nach §21 gebaut und gefahren (Ergebnisse: `PRUEFBERICHT.md`):
  - `SiegelFuzz` (nur Debug-Bau, `@testable` für den KDF-Testschalter und interne Parser; im Release-Bau nur ein
    Hinweis) mit den Zielen `datei`, `inhalt` (mit dem DEK neu verschlüsselte Inhalte bis `UnlockedVault`, Bericht,
    Aufdecken und Notfallweg), `notfall`, `karte`, `csv`, `totp`, `cbor`, `ctaphid` (ganze FIDO2-Abläufe gegen ein
    gestörtes Gerät), zusätzlich `hwdatei` (Schlüsseldatei §14.1), `sicherung` (Namen am frei gewählten zweiten Ort,
    Ausdünnung) und `autofill` (§20). Rückkopplung über Kanten-Abdeckung (`-sanitize-coverage=edge,trace-pc-guard`,
    eigene Rückrufe im C-Ziel `SiegelFuzzAbdeckung`; libFuzzer liefert Apples Werkzeugkette nicht mit) und über neue
    Ergebnis-Codes; Zeitlimit pro Eingabe, gesicherte Eingaben bei Absturz/Hänger/Fund. Ziele und Invarianten:
    `Sources/SiegelFuzz/FUZZ-NOTIZEN.md`.
  - AddressSanitizer läuft ohne Globals-Instrumentierung (`-Xllvm -asan-globals=0`): Die Wortlisten-Literale (um 1 MB)
    überschreiten mit Redzone die Symbolgrenze von `ld`. Heap, Stack und use-after-return bleiben geprüft.
  - Unter Sanitizern strecken die Tests ihre Laufzeitgrenzen (`SIEGEL_ZEITFAKTOR`, sanitizer.sh setzt 12 bzw. 30), und
    der Exit-Test zur Seed-Länge (Befund #20) schaltet sich ab: Sein Kindprozess lädt die Sanitizer-Laufzeit zu spät
    und startet nicht. Im normalen `swift test` laufen beide unverändert.
  - Differenztest Swift ↔ Python `referenz/differenz.sh` (Mutanten der Beispieldateien vom Fuzzer).
- Verworfen (v4): SMS-/E-Mail-Bestätigung als Faktor: bräuchte einen Server (bricht „kein Netzwerk“), wäre lokal nur
  eine Tür in der Oberfläche, und SMS gilt als schwacher Faktor (SIM-Swapping). Ersatz: QR-Karte und geteilter
  Notfallcode.
- Verworfen (v4): Data-Protection-Schlüsselbund und Team-Signatur: Das kostenlose Team liefert nur Profile mit
  7 Tagen Laufzeit; CryptoKit-Secure-Enclave-Schlüssel mit eigener Blob-Ablage funktionieren ad-hoc (gemessen).
- v4.3 (17.10.2026): Selbstvernichtung nach Wunsch des Nutzers (§23): Totmann-Schalter, Fehlversuch-Zähler und
  Vernichtungs-Passwort, nur Tresor-Stufe 4/5 und nur für ausgewählte Einträge mit Schutz 4/5; Vernichtung über
  einen eigenen Secure-Enclave-Schlüssel (Krypto-Löschung), vernichtbare Einträge ohne Notfallweg. Ersetzt für
  diesen Bereich den früheren Entscheid „Versuchsgrenzen/Selbstlöschung verworfen“: Er gilt weiter als Standard,
  die Selbstvernichtung ist ausdrücklich gewählt, mit ehrlichen Grenzen in Oberfläche und SICHERHEIT.md.
  Nach der Integration bewusst anders gelöst bzw. festgelegt (geht §23 vor):
  - §23.3 Schnittstelle: `configureDestruction` gibt `PurgeReport?` zurück (`@discardableResult`): Werden Einträge neu
    markiert, entfernt der Kern danach alle älteren Sicherungen (sie enthielten die Einträge noch mit Notfall-Umschlag,
    die Vernichtung wäre über sie umgehbar; Time-Machine-Kopien bleiben ausserhalb seiner Reichweite). Dazu eine
    async-Variante (`@concurrent`) mit `entryFactors: EntryFactorProvider?` wie in v4.1: neu markierte Einträge werden
    über ihre Notfall-Gruppe geöffnet (eine Freigabe je Gruppe), abgewählte über V (Touch ID je Eintrag); die synchrone
    Signatur wirft `factorMissing(.secureEnclave)`, sobald etwas neu zu versiegeln ist. `duressPassword` nil =
    bisheriges behalten (nur mit `duressEnabled`, sonst `io("destruction.duressPassword")`), `vKey` nil = bisheriges V.
    V ist Pflicht, sobald ein Auslöser an oder ein Eintrag markiert ist; ein ersetztes oder nicht mehr gebrauchtes V
    vernichtet der Kern nach dem Schreiben selbst. `destructible` ist immer die ganze Auswahl.
  - Zusätzlich öffentlich: `DestructionStatus.destroyedTrigger`/`destroyedAt` (statt des Tupels) mit Init und den
    Helfern `remainingAttempts`, `shouldWarnAboutAttempts` (ab N/2), `deadlineIsNear(now:)` (≤ 25 % Restzeit);
    Init und Bereiche von `DestructionSettings`; `UnlockedVault.destructionSettings`, `destructibleEntries` (in einer
    Vernichtungs-Sitzung leer), `destructionKeyID`, `destructionStatus` (sitzungsgerecht, verrät in einer
    Vernichtungs-Sitzung nichts; `VaultStore.destructionStatus()` dagegen schon – die Oberfläche zeigt bei offenem
    Tresor nur den sitzungsgerechten); `VaultStore.destructionKeyEraser` (austauschbare Schicht, die App setzt
    `SecureEnclaveFactor.destroy`, Rückfall `FileDestructionKeyEraser` im Kern) und `ClosureDestructionKeyEraser`.
  - §23.2 Nr. 1: Echtes Entsperren setzt `lastGenuineUnlock = max(alt, jetzt)` – eine zurückgestellte Uhr verlängert
    nicht und löst später, wenn sie wieder stimmt, nicht falsch aus.
  - §23.2 Nr. 2: Der Zähler zählt `wrongPassword` auch auf den Sicherungswegen (`restoreBackup`, `importBackup`,
    `restoreNewestReadableBackup`), sonst liesse er sich dort umgehen. Das Vernichtungs-Passwort wirkt nur beim
    normalen Entsperren und zählt auf diesen Wegen als Fehlversuch; erkannt setzt es den Zähler wie ein echtes
    Entsperren auf 0 (die Warnung verriete sonst die Sitzung).
  - §23.2 Nr. 3: Die Ablage des Vernichtungs-Passworts hat die Form der SE-Schlüsseldateien (`SIEGELHW`, kind 2,
    gültiger P-256-Punkt), aber feste 2048 B (ML-KEM-1024-Chiffrat); die SE-Schlüsseldateien werden **nicht** auf
    diese Grösse gepolstert (§14.1 unverändert), weil `zustand.json` nach §23.3 die Einstellungen und damit auch das
    eingeschaltete Vernichtungs-Passwort samt Ablage-Kennung nennt – die gleiche Form schützt nur vor einem
    flüchtigen Blick (ehrliche Grenze, SICHERHEIT.md). Solange ein Vernichtungs-Passwort aktiv ist, ist ein anderes
    KDF-Profil gesperrt (`notAllowedAtLevel`, beide Argon2 brauchen dieselben Parameter); ein neues Master-Passwort
    gleich dem Vernichtungs-Passwort → `masterPasswordReused`.
  - Vernichtungs-Sitzung: Alles, was das Master-Passwort verlangt (`verify`, Passwortwechsel, Notfallkit, Stufe,
    Faktoren, Selbstvernichtung), meldet nach gleich langer Rechnung `wrongPassword` – sonst könnte sie den Zugang des
    Besitzers ersetzen, und das nächste Öffnen verriete die Vernichtung (ehrliche Grenze: wer das mehrfach probiert,
    kann Verdacht schöpfen). Beim Öffnen schreibt sie nur V (vernichten) und `zustand.json`.
  - Notfallweg (`recover`, auch über Sicherungen): vernichtbare Einträge fallen ganz weg (sie haben keinen
    Notfall-Umschlag), auch vor einer Vernichtung; die Selbstvernichtung ist danach aus. Die Oberfläche warnt im
    Notfallweg allgemein (die Zahl ist gesperrt nicht bekannt).
  - Nach einer Vernichtung lehnt `configureDestruction` bis `removeDestroyedEntries()` ab
    (`io("destruction.destroyed")`); danach ist die Selbstvernichtung ganz aus (V verbraucht, neu einrichten mit neuem
    V). Stufe < 4 ist gesperrt, solange etwas eingerichtet ist (`notAllowedAtLevel`, die Oberfläche sagt es schon in
    der Stufenwahl).
  - Inhalt: Ohne Selbstvernichtung fehlt der Schlüssel `destruction` ganz (Abweichung von „null explizit“, damit
    bestehende Inhalte bytegleich bleiben); vernichtbare Einträge stehen mit `"recovery": null`.
  - Offen (Entscheid des Nutzers): Vernichtbare Einträge behalten bis zum Entfernen ihren reuseTag (§17; Bericht,
    Wiederverwendung). Wer das Master-Passwort hat, kann damit Vermutungen für ein vernichtetes Passwort prüfen
    (erzeugte Passwörter sind so nicht zu erraten); ohne reuseTag fehlten sie im Bericht.
- v4.4 (17.10.2026): Nach der zweiten Prüfung (Krypto-Befunde krypto-1 bis krypto-3) bewusst geändert (geht §17 und
  §23 vor):
  - §23.2 Nr. 3 (krypto-1): Der Umschlag des Vernichtungs-Passworts ist an die Faktoren der Stufe gebunden:
    `F = HKDF-SHA512(e ‖ c ‖ [y] (Faktor-Schlüssel wie §13.1), salt = vaultID, info = "Siegel v2 duress factors" ‖
    factorMask, 32)`, `kek = HKDF-SHA512(Kombinierer (Label "Siegel v2 duress", Zusatzfeld fileID) ‖ F, salt = fileID,
    info = "Siegel v2 duress kek", 32)`. Bisher genügten eine Kopie des Containers und das Vernichtungs-Passwort für den
    DEK (Liste, Titel, Benutzer, Websites, alle Einträge mit Schutz 1): In Stufe 4/5 war es so ein zweites
    Master-Passwort ohne Faktoren, entgegen §13 („keine Tür in der Oberfläche“). Der Prüfwert hängt weiter nur an `d`:
    Erkannt und vernichtet wird auch bei falschem Faktor, dann aber `wrongPassword` statt einer Sitzung. Die Sitzung hält
    F in `SecureBytes`, damit jedes Speichern neu kapseln kann; ein Stufenwechsel rechnet F mit den Faktoren der
    Zielstufe neu. `persist` schreibt einen Inhalt mit Vernichtungs-Passwort nie ohne F (`crypto("duress.binding")`,
    vor dem Schreiben). Ablagen aus v4.3 (ungebunden) erkennen nur noch; darum kapselt jedes echte Entsperren die Ablage
    neu (statt nur bei Abweichung). Ersetzt „kryptografisch braucht der Vernichtungsweg sie nicht“.
  - §1.2/§23 (krypto-2): Die Vernichtungs-Sitzung arbeitet mit dem echten DEK. Sie vermerkt `"rekeyPending": true` in
    `zustand.json` (nur dann steht der Schlüssel da); das erste echte Entsperren danach erneuert DEK und Salz (gleiche
    Stufe, Faktoren, Kit und KDF, ein Argon2 mehr) und schreibt sofort – nicht bei Rollback-Verdacht (dort entscheidet der
    Nutzer); scheitert das Schreiben, öffnet der Tresor trotzdem, und das nächste echte Entsperren versucht es neu. Jedes
    Schreiben mit neuem DEK erledigt den Vermerk. Das Vernichtungs-Passwort bleibt danach eingerichtet (wer es unter
    Zwang erneut nennen muss, braucht dieselbe Wirkung); offline hilft es wegen der Bindung nur mit den Faktoren.
    Ersetzen oder Entfernen des Vernichtungs-Passworts in `configureDestruction` ist ein Zugangswechsel (§1.2): neuer DEK
    (ein Argon2 mehr). `removeDestroyedEntries()` schaltet mit der ganzen Selbstvernichtung auch das
    Vernichtungs-Passwort aus und rotiert nicht (kein Passwort zur Hand); nach einer Vernichtungs-Sitzung ist der DEK
    dann schon erneuert.
  - §17 (krypto-3): `reuseTag` über `OpaqueString(password)` (§1.1: Zs → U+0020, dann NFC) statt nur NFC. Sonst fand der
    Abgleich mit dem (so abgebildeten) Master-Passwort versiegelte Einträge mit z. B. U+00A0 nicht: `changeMasterPassword`
    lehnte das Passwort nicht ab (§1.6), „Gleich wie Master-Passwort“ fehlte. Alte Tags: Offene Einträge bekommen beim
    nächsten Speichern den neuen Tag, ohne neues Änderungsdatum; versiegelte behalten ihn bis zum Neu-Versiegeln. Für sie
    rechnet der Kern zusätzlich den Tag nach der alten Formel aus der rohen Eingabe des Master-Passworts (Entsperren,
    Passwortwechsel, Sicherung einsetzen) und beim CSV-Import. Ehrliche Grenze: Mit U+0020 statt U+00A0 getippt erkennt
    er solche alten Tags nicht. Der Notfallweg war nicht betroffen (er entsiegelt vor der Prüfung alles).
- v4.4 (17.10.2026), Datei-Befunde datei-1 bis datei-5 der zweiten Prüfung (geht §4, §8, §22 und §23 vor):
  - Schreiben nach dem Sperren (datei-1): Nach `lock()` schreibt ein offener Tresor nichts mehr. Jeder Weg zur Platte
    (`save`, Zugangswechsel, Stufe, Kit, `configureDestruction`) prüft unmittelbar vor `persist` unter `writeLock`, ob
    gesperrt ist (`io("vault.locked")`, Datei unverändert) – sonst schrieb z. B. `configureDestruction` nach einem
    App-Wechsel während des Argon2 fürs Vernichtungs-Passwort den Inhalt mit den an das neue V versiegelten Einträgen,
    warf danach `vault.locked`, und die Oberfläche vernichtete dieses V (Einträge verloren, Einstellung festgehalten).
    Nach einem erfolgreichen Schreiben wirft `configureDestruction` nicht mehr: Die Generation kommt aus dem Schreiben,
    ein Fehler in `purgeBackups` landet im Bericht (`PurgeReport.interrupted = true`, `isComplete == false`; die
    Oberfläche meldet „Ältere Sicherungen liessen sich nicht entfernen“). Neu `VaultStore.destructionKeyIsUnused(_:vaultID:
    generation:) -> Bool`: true nur, wenn `zustand.json` V weder als V noch als vernichtet nennt (unlesbar = nennt) und
    die Tresordatei noch genau die Generation vor dem Aufruf hat. Die Oberfläche vernichtet ein neues V nach einem
    Fehler nur dann, nach einem Fehler in einer inzwischen gesperrten Sitzung nie (eine verwaiste V-Datei ist harmlos).
  - Notfallweg ohne Tresordatei (datei-2): „Tresor fehlt“ bietet „Passwort vergessen? Notfallcode verwenden“ und, wenn
    ein Faktor der Sicherung nicht nutzbar ist, „Notfallcode verwenden“ in der Faktor-Zeile (§14.1). `vaultMissing` beim
    Prüfen gegen die Datei führt zu den Sicherungen (ohne Datei alle, §4), Code bzw. Teile stellen über
    `recoverFromNewestReadableBackup` her; die Wahl Code/Teile kommt aus dem Kopf der neuesten lesbaren Sicherung.
    „Zurück“ führt dorthin, wo es passt (Sperrbildschirm, „Tresor fehlt“, Einrichtung).
  - Notfallweg für eine gewählte Sicherung (datei-3): Neu `VaultStore.recoverBackup(from:code:newMasterPassword:kdf:)`
    und `recoverBackup(from:shares:newMasterPassword:kdf:)`, dazu `checkRecoveryCode(_:againstFile:)` und
    `checkRecoveryShares(_:againstFile:)` (Korrektur wie §1.5). Gemessen am eigenen Kopf der Datei, egal zu welchem
    Tresor sie gehört (der Nutzer wählt sie ausdrücklich; die Kit-Sperre des automatischen Wegs bleibt), Ablauf wie
    `recover`: entsiegeln, Master-Tag, Stufe 1, neuer DEK, neues Salz; eine bisherige Tresordatei bleibt als
    angeheftete Sicherung „vor-notfall“. Fehlt die Datei → `io("backup.missing")`. Neu `VaultStore.backupInfo(fileAt:)`
    (Stand, vaultID, Änderungsdatum, ohne Schlüssel) und `backupsDirectory`. Oberfläche: Einrichtung „Aus Sicherung
    wiederherstellen…“ (neuer Mac), „Andere Sicherung wählen…“ bei „Tresor fehlt“; „Beschädigt → Sicherung aus Datei
    einspielen…“ und Einstellungen → „Sicherung einspielen…“ bieten bei `factorUnavailable` „Notfallcode verwenden“ für
    genau diese Datei (das Panel öffnet im Ordner der Sicherungen, so sind auch Sicherungen von vor einer Abstufung
    erreichbar). Das Notfallkit-Blatt nennt den Weg auf einem neuen Mac.
  - Kopf bei beschädigtem Inhalt (datei-4): Neu `VaultStore.inspectHeaderUnverified()` und
    `inspectHeaderUnverified(fileAt:)` (nur der Kopf, ohne Prüfsumme; ausdrücklich ungeprüft, nur für die Wahl Code oder
    Teile). Der Notfallweg nimmt: geprüften Kopf, sonst ungeprüften, sonst den der neuesten lesbaren Sicherung. Ist der
    Kopf nicht geprüft aus der Zieldatei gelesen, gibt es den Umschalter „Ich habe ein Kit in drei Teilen“ / „Ich habe
    einen einzelnen Code“; ein Teil (56 Zeichen) im Code-Feld wechselt von selbst zur Eingabe der Teile. Das KDF-Profil
    bleibt auf Standard/Stark beschränkt (§4, Befund #21).
  - Fehlversuche auf den Sicherungswegen (datei-5): Die Warnung „Noch x Versuche bis zur Vernichtung“ (§23.2, ab N/2)
    steht auch bei „Tresor fehlt“, „Beschädigt“ und „Sicherung einspielen…“; nach jedem `wrongPassword` dort liest die
    Oberfläche den Zähler neu (beim Betreten ebenfalls). Wie bisher zählt das Vernichtungs-Passwort auf diesen Wegen als
    Fehlversuch (v4.3).
- v4.4 (17.10.2026), Hardware-Befunde hardware-1 bis hardware-4 der zweiten Prüfung (geht §14, §21 und §22 vor, ersetzt
  in v4.1 „Sperre … → `factorUnavailable`“):
  - Touch ID gesperrt oder nicht erreichbar (hardware-1): Neuer `SiegelError.factorTemporarilyUnavailable(FactorKind,
    String)` mit festen Codes `"se.lockout"` (LAError `biometryLockout`, nach zu vielen Fehlversuchen) und
    `"se.notReachable"` (`biometryNotAvailable`, `biometryDisconnected`, `biometryNotPaired`: Deckel zu, Tastatur mit
    Touch ID nicht verbunden). SiegelHardware erkennt sie in der Fehlerkette; ist ein Fehler weder Abbruch noch so
    erkennbar (CryptoKit/CryptoTokenKit verpacken nicht immer gleich), fragt es ohne Dialog den Zustand von Touch ID
    (`canEvaluatePolicy`) und meldet bei Sperre bzw. unerreichbarem Sensor ebenfalls den vorübergehenden Fall.
    `factorUnavailable(.secureEnclave)` („Schlüssel fehlt oder Fingerabdrücke geändert“, mit Notfallweg) gibt es nur
    noch, wenn die Schlüsseldatei fehlt oder Touch ID bereit ist und der Schlüssel trotzdem abgelehnt wird (auch: keine
    Finger mehr eingerichtet). Die Oberfläche bietet beim vorübergehenden Fall keinen Notfallweg an (er setzte auf
    Stufe 1 zurück und liesse vernichtbare Einträge wegfallen), „Erneut versuchen“ ist der Hauptknopf; der leise
    Notfallweg des Sperrbildschirms bleibt (z. B. für einen Mac ohne Touch ID). Gleich in der Stufenregel „Touch ID vor
    dem Aufdecken“. Verworfen: Knopf „Mit Mac-Passwort freigeben“ (`deviceOwnerAuthentication`): ungetestet ohne
    Dialog; der Text nennt den Weg über den Sperrbildschirm des Macs.
  - Signatur-Selbstprüfung (hardware-2): `AppModel.production(signatureIsValid:)` prüft `CodeSignatureCheck
    .mainBundleIsValid()` als Erstes und synchron (vor Datenordner und Einzelinstanz); ungültig → `BlockReason
    .signatureInvalid` („Siegel ist beschädigt“, ohne Tresor, also ohne Entsperren, Wiederherstellen oder Einspielen).
    Ehrlich: Eine veränderte Datei in `Resources` löst die Meldung aus; ein verändertes Programm beendet macOS
    (Hardened Runtime) schon vorher.
  - Anderer Sicherheitsschlüssel (hardware-3): Neuer `SiegelError.wrongSecurityKey` (analog `wrongCard`) für
    CTAP2_ERR_NO_CREDENTIALS (0x2E): anderer oder zurückgesetzter Schlüssel. Meldung „Das ist nicht der
    Sicherheitsschlüssel dieses Tresors …“, Notfallweg wie bei `factorUnavailable`.
  - Abbrechen beim Sicherheitsschlüssel (hardware-4): Neu `SecurityKeyCancellation` (SiegelHardware, Sendable) als
    optionaler Parameter von `SecurityKeyFactor.register(on:cancellation:)` und `secret(on:credentialID:salt:
    cancellation:)`. Der CTAPHID-Kanal wartet höchstens 100 ms am Stück und prüft dazwischen das Token, auch im Warten
    bei ERR_CHANNEL_BUSY; gesetzt → offene Anfrage mit CTAPHID_CANCEL (CTAP 2.1 §11.2.9.1.5) beenden, Verbindung
    schliessen, `factorCancelled`. Die Oberfläche setzt es bei „Abbrechen“ und beim Sperren. Belegt über die ganze
    Frist (ERR_CHANNEL_BUSY) → `factorTemporarilyUnavailable(.securityKey, "fido.busy")`. Das Kamera-Sheet stoppt beim
    Umschalten auf „Abtippen“ die Kamera (§14.2: nur bei Bedarf) und startet sie bei „Kamera verwenden“ wieder.
- v4.4 (17.10.2026), Hygiene-Befunde hygiene-1 bis hygiene-5 der zweiten Prüfung (geht §6, §13, §16 und §23.2 vor):
  - Sperren mit geschützter Bearbeitung (hygiene-1): Bisher übersprang „Sperren ohne Datenverlust“ den versiegelten
    Weg, wenn für den gewählten Schutz ein Faktor fehlte, und legte nach dem gescheiterten `upsert` still eine
    Klartext-Kopie „Entwurf …“ mit Schutz 1/2 an (auch von vernichtbaren Einträgen, mit Notfall-Umschlag, ohne 2FA, ohne
    Hinweis). Jetzt (§6 a): geschützte, vernichtbare und vernichtete Einträge nur versiegelt; Schutz = gewählter, wenn
    eingerichtet, sonst der höchste eingerichtete zwischen bisherigem (neu: Vorgabe der Stufe und Einstellung) und
    gewähltem, mit Hinweis auf dem Sperrbildschirm und nach dem Entsperren („Die offene Bearbeitung ist mit Schutz 3
    statt 4 gespeichert – für Schutz 4 fehlt noch: QR-Schlüsselkarte.“). Scheitert `setProtection` (z. B.
    `io("entry.destroyed")`, wenn der Totmann-Schalter während der Bearbeitung vernichtet), bleiben nur die Metadaten,
    der Hinweis sagt es, ⌘L wird abgelehnt. Die Klartext-Kopie nur noch bei Schutz 1 vorher und nachher, mit 2FA und
    Hinweis „Als Entwurf gespeichert“. Der Sperr-Teilnehmer meldet dafür `doneWithNotice` bzw. `lost(_, notice:)`.
  - Zwischenablage beim App-Wechsel (hygiene-2): Die Sperre beim App-Wechsel (Stufe 3–5) leerte die Zwischenablage
    sofort – kopierte Passwörter liessen sich nirgends einfügen, „wird in 15 s gelöscht“ stimmte nicht. Jetzt leert
    jeder Anlass ausser `.deactivated` sofort; nach dieser Sperre läuft der Ablauf (≤ 15 s) weiter, eine Aktivität
    verhindert App Nap bis zum Leeren, und Ruhezustand, Bildschirm aus, Bildschirmsperre und Benutzerwechsel leeren auch
    ohne offenen Tresor (vor der Prüfung, ob die Auto-Sperre scharf ist). Verworfen: die Sperre beim App-Wechsel
    aufschieben, bis die Zwischenablage abläuft (der Tresor bliebe offen, während ein anderes Programm vorne ist).
  - ⌘C aus Geheimnis-Feldern (hygiene-3): Die Dauer war ein globaler Wert ohne Eintrags-Schutz (90 s bei Schutz 3) und
    nach einer Änderung der Einstellung bis zum nächsten Neulesen ohne Grenze der Stufe. Jetzt bestimmt ein Provider des
    Modells sie beim Kopieren (`effectiveClipboardSeconds(max(gewählter, bisheriger Schutz))` beim Bearbeiten, sonst
    Schutz 1; ohne Modell 15 s).
  - Kamera-Vorschau (hygiene-4): Die Vorschau beim Scannen der Karte zeigte den QR-Code auch auf Sidecar, Beamer und
    gespiegelten Bildschirmen; sie liegt jetzt wie die Kartendarstellung im Assistenten hinter der Verdeckung (§6), mit
    „Hier zeigen“. Sucher, Häkchen und die Erkennung bleiben.
  - Totmann-Frist nach einer Vernichtung (hygiene-5): Der Sperrbildschirm zeigte die Frist nach einer
    Vernichtungs-Sitzung unverändert weiter (ein echtes Entsperren hätte sie verschoben) – ein Hinweis auf das
    Vernichtungs-Passwort ohne Dateizugriff. Jetzt keine Frist, sobald `destroyedAt` vermerkt ist (§23.2); der Vermerk
    steht in `zustand.json`, gilt also auch nach einem Neustart.
- v4.4 (17.10.2026), Ablauf-Befunde ablaeufe-1 bis ablaeufe-10 der zweiten Prüfung (geht §6, §7, §16, §22 und §23 vor).
  Schon mit anderen Befunden behoben: ablaeufe-1 (= hygiene-1), ablaeufe-2 (= hygiene-2), ablaeufe-6 (= datei-5),
  ablaeufe-8 (= hygiene-3), ablaeufe-9 (= hardware-1); dazu hier nur Ergänzungen. Neu:
  - Sperrbildschirm nach einer Vernichtungs-Sitzung (ablaeufe-3, ergänzt hygiene-5): `lock()` verwirft den Stand der
    Sitzung (`destruction = nil`), bis `route()` ihn aus `zustand.json` gelesen hat – sonst stand bis dahin der
    sitzungsgerechte Stand der Vernichtungs-Sitzung (ohne Vernichtung, alte Frist) auf dem Sperrbildschirm. Der
    Totmann-Takt liest nach seiner Sperre selbst neu.
  - Faktor-Abfragen nach dem Sperren (ablaeufe-4): `UIEntryFactorProvider` gehört zur Sitzung, in der er entstand
    (`epoch`, offener Tresor); danach → `factorCancelled`, ohne Sheet, Kamera oder Touch-ID-Dialog. Der Kern prüft
    zusätzlich vor jeder Freigabe (`LockCheckedEntryFactors` beim Aufdecken, in `releaseGroups` auch vor der ersten)
    und wirft `io("vault.locked")`, ohne den Provider zu rufen: Wer während Touch ID oder während des Argon2 eines
    Exports, Kit- oder Stufenwechsels sperrt, sieht danach weder Kamera-Sheet noch Schlüssel-Sheet noch
    „Eintrag aufdecken“ über dem Sperrbildschirm. Verworfen (vorerst): einen schon offenen Touch-ID-Dialog beim
    Sperren per `LAContext.invalidate()` schliessen – ohne Dialog nicht prüfbar; der Dialog liefert danach nichts mehr
    an Siegel weiter.
  - Markierte Einträge ohne Auslöser (ablaeufe-5): `DestructionStatus` hat neu `keyConfigured: Bool` (V eingerichtet
    oder vernichtet; aus `zustand.json`, also auch gesperrt; in beiden Sitzungsarten gleich; nicht geheim, die Datei
    nennt V ohnehin). Die Warnung im Notfallweg hängt an `DestructionRules.isConfigured` (Auslöser an oder V), die
    Zeile in den Einstellungen zeigt dann „Einträge markiert · kein Auslöser“ statt „Aus“, der Entwurf sagt „Ohne
    Auslöser wird nichts vernichtet – die markierten Einträge haben trotzdem keinen Notfallweg.“
  - Sicherungswege (ablaeufe-6, ergänzt datei-5): Bei aktivem Zähler sagt die Meldung zum falschen Passwort „Auch hier
    zählt jeder Fehlversuch.“ (schon vor N/2: ältere Sicherungen öffnen mit früheren Passwörtern, das lädt zum
    Durchprobieren ein).
  - „Jetzt einrichten…“ in der Bearbeitung (ablaeufe-7): öffnete nichts (die Sperre aus Befund #36 hielt auch den
    Assistenten zurück). Jetzt zeigt `startEnroll(fromEditor: true)` die Einstellungen direkt (`presentSettings`),
    nur mit dem Assistenten; „Zurück zum Eintrag“, Esc und „Fertig“ führen in die Bearbeitung zurück, der Entwurf und
    „Sperren ohne Datenverlust“ bleiben. Ein Sperren während `wizardApply` wartet beim Sichern des Entwurfs höchstens
    auf das eine Argon2 von `enrollFactors` (der Kern hält dabei den Schreib-Lock) – nicht auf zwei wie beim
    Passwortwechsel in #36. Verworfen: ⌘L währenddessen ablehnen (wer sperrt, will sperren).
  - Zwischenablage gesperrt (ablaeufe-8, ergänzt hygiene-3): Gesperrt gilt für ⌘C aus den Notfallcode-Feldern die
    Grenze der zuletzt geöffneten Stufe (`lastClipboardMax`, wie `lastAutoLockMax`), nicht die rohe Einstellung.
  - Autofill (ablaeufe-9, ergänzt hardware-1): Die Erweiterung meldet `factorTemporarilyUnavailable` als Sperre bzw.
    unerreichbares Touch ID, ohne Notfallweg.
  - Sicherungen im Hintergrund (ablaeufe-10): `store.backups()` liest jede Datei ganz (Prüfsumme), am zweiten Ort z. B.
    aus iCloud Drive nachgeladen – nicht mehr auf dem Main-Thread. „Tresor fehlt“ erscheint sofort mit „Sicherungen
    werden gesucht…“ (erst nach 0.4 s sichtbar) und füllt die Liste aus dem Hintergrund; ohne lesbare Sicherung danach
    die Einrichtung. Ohne jede Datei im Ordner der Sicherungen und ohne zweiten Ort entscheidet `route()` weiter sofort
    (nur Verzeichnisse gelistet). Ebenso im Hintergrund: Liste neu lesen, „Aus Sicherung wiederherstellen…“, ein eben
    verbundener zweiter Ort in der Einrichtung, „Neueste lesbare Sicherung öffnen“ (mit Fortschritt). Die volle Prüfung
    pro Datei bleibt (sie ist die Grundlage für „lesbar“); `restoreNewestReadableBackup` liest die Liste im
    Hintergrund ein zweites Mal (bewusst: keine neue Kern-Schnittstelle).
- v4.4 (17.10.2026), Bau-Befunde bau-1 bis bau-4 der zweiten Prüfung (geht §5, §6, §9 und §20 vor):
  - Touch ID kurz nicht verfügbar (bau-1, ergänzt hardware-1/ablaeufe-9): Die Erweiterung behandelte
    `factorTemporarilyUnavailable` noch als endgültig (nur „Schliessen“). Jetzt nicht endgültig: beim Entsperren
    zurück zum Passwortfeld, beim Aufdecken zurück zur Liste, Text ohne Notfallweg („gesperrt … mit deinem Passwort
    entsperren“ bzw. „Deckel zu oder Tastatur mit Touch ID nicht verbunden …“). Den Notfallcode nennt sie nur noch bei
    `factorUnavailable`/`factorMissing`. In der App ist „Erneut versuchen“ neben „Notfallcode verwenden“ ein Knopf mit
    Rahmen statt eines leisen Links (die Diagnose „Schlüssel fehlt“ kann sich irren, der Notfallweg setzt auf Stufe 1).
  - Eingefügtes Master-Passwort in der Erweiterung (bau-2, §6): Wie die App merkt sich die Erweiterung beim Einfügen
    ins Passwortfeld (Text wird länger, kein einfaches Tippen) nur den `changeCount` und leert die Zwischenablage nach
    dem Entsperren und beim Aufräumen (Auswahl, Abbruch, Frist), wenn sie unverändert ist; nach dem Entsperren steht
    „Zwischenablage geleert – sie enthielt dein Master-Passwort.“ Der Inhalt wird nie gelesen. Eigene ~20 Zeilen in
    der Erweiterung (sie bindet SiegelUI nicht ein). Verworfen: den Tracker in ein gemeinsames AppKit-Modul ziehen
    (neues Produkt für App und Erweiterung, Aufwand ohne Mehrwert).
  - Meldung nach gescheiterter Auswahl (bau-3): „Touch ID abgebrochen.“ u. a. wurde von der Liste sofort überschrieben.
    Jetzt steht die Meldung vor dem Hinweis auf die Anzahl („… 12 Einträge passen, gezeigt werden die ersten 8.“);
    beim erneuten Wählen verschwindet eine alte Meldung.
  - Testbarkeit der Erweiterung (bau-1 bis bau-3): Package.swift übersetzt dieselben Quellen
    (`Erweiterungen/SiegelAutofill/*.swift`) zusätzlich als Bibliothek `SiegelAutofillErweiterung` (kein Produkt, geht
    in keine App ein), `Tests/SiegelAutofillTests` prüft die Abläufe mit einer Test-Zwischenablage, ohne System-Dialog.
    So übersetzt auch `swift build` die Erweiterung, nicht erst `skripte/autofill_bauen.sh`.
  - Grep-Sperren (bau-4, §5): `NSLogv` ist gesperrt wie `NSLog`. Ein einfaches Regex-Literal `/…/` erkennt der Lexer
    auch nach `+ - * < > % ^ ~` und nach `try`, `await`, `in`, `throw`, `case`, `where`, `else`, `guard`, `if`,
    `while`, `switch`, `return`, `yield` (vorher las er z. B. `try /[^"]+/` als Division, das `"` öffnete eine
    Zeichenkette und blendete den Rest der Zeile aus, bei `"""` sogar die folgenden Zeilen). Rückfallnetz: Hält die
    Heuristik ein `/` für eine Division, obwohl ein `/…"…/` folgt, prüft ein zweiter Lauf mit Regex-Literal; gemeldet
    wird, was einer der Läufe findet. Der Selbsttest enthält die Beispiele des Befunds.
- v4.4 (17.10.2026), Design-Befunde design-1 bis design-7 der zweiten Prüfung (geht §7, §13 und §16 vor):
  - „Jetzt einrichten…“ in der Bearbeitung (design-1): schon mit ablaeufe-7 behoben (`presentSettings`, Assistent
    sichtbar, Bilder 107/108/112 verschieden; Sperren währenddessen wartet höchstens auf ein Argon2).
  - Sperrbildschirm im kleinsten Fenster (design-2, §23.2): Die Totmann-Frist ist eine eigene Zeile über „Notfallcode
    verwenden“ (vorher eine Überlagerung mit festem Versatz, die bei 760×480 in die Zähler-Warnung lief); der Abstand
    Logo → Feld bleibt eine Scheibenhöhe und gibt erst nach, wenn die Ränder auf ihrem Minimum sind. Das
    Snapshot-Programm misst die Rahmen (`LayoutRecorder`, nur mit gesetztem Sammler aktiv) bei 920×600 und 760×480.
  - Sicherung exportieren (design-3, §4/§13): Der Text richtet sich nach dem Kopf. Ab Stufe 2 ist die Sicherung als
    Kopie der Datei an Touch ID **dieses** Macs gebunden (ab Stufe 4 dazu Karte bzw. Schlüssel); auf einem anderen Mac
    öffnet sie nur der Notfallcode bzw. zwei der drei Teile (Einrichtung → „Aus Sicherung wiederherstellen…“, datei-3).
    Den verlorenen Mac übersteht sie dann nur zusammen mit dem Notfallkit. „Sicherung einspielen“ nennt die Faktoren.
  - Karte abtippen (design-4): Feld „Kartencode, 11 Gruppen“ (der Code steht neben dem QR-Code, nicht darunter);
    `CardScanState.typingMessage` als eigene Kopfzeile beim Abtippen – nach „Code von Hand abschreiben“ „Tippe den Code
    ab, den du eben notiert hast …“, im Kamera-Modus der Kameratext.
  - Schutz-Auswahl (design-5, §16): Kurztexte „Touch ID und Karte · nicht im Export.“ und „Touch ID, Karte, Schlüssel ·
    nicht im Export.“ passen neben „noch einrichten“ und drei Symbolen in die 540-pt-Spalte; voller Text auch als Tooltip.
  - Stufe Maximal (design-6, §13): „Kein CSV- und KeePass-Export“ statt „Kein Klartext-Export“ (KeePass ist
    verschlüsselt, aber ebenso gesperrt); die Detailbox hängt an beiden Regeln.
  - Sprache (design-7): „die Secure Enclave“ (wie Apple) in Oberfläche, SPEC und SICHERHEIT.md.
- v4.5 (17.10.2026): Selbstvernichtung im Fuzzer (dritte Prüfrunde, `PRUEFBERICHT.md` §8; geht §21 und §23 vor). Das
  neue Fuzz-Ziel `vernichtung` fand acht Fehler im Kern (vernichtung-1 bis -8), alle behoben, je mit Regressionstest
  (Suite „Fuzz-Befunde: Selbstvernichtung“; Tabelle in `Sources/SiegelFuzz/FUZZ-NOTIZEN.md`):
  - Grenze (bewusst, SICHERHEIT.md): `zustand.json` ist gesperrt nicht prüfbar; ein veränderter Zustand kann auslösen
    und löscht, was er als V bzw. vernichtet nennt. Aber ein Zustand, der den Entsperr-SE-Schlüssel des Kopfes nennt,
    gilt nicht – ohne lesbaren Kopf die Entsperr-SE-Schlüssel der eigenen Sicherungen (vernichtung-1, -6) –, und der
    Vermerk nach dem Vernichtungs-Passwort liest über dieselbe Prüfung (vernichtung-4, Wettlauf zwischen Probe und Vermerk).
  - Als veraltete Ablage löscht der Kern nur eine Datei, die wirklich eine Ablage ist, nie einen Schlüssel in Gebrauch
    (vernichtung-2, -7); eine Ablage ersetzt beim Schreiben nur eine Datei in Ablage-Form (vernichtung-8). V,
    Ablage-Kennung und Eintrags-SE-Schlüssel sind paarweise verschieden und nie der Entsperr-SE-Schlüssel
    (`checkDestruction`, `destructionKeysAvoid`: Lesen `corruptFile`, Schreiben `crypto("payload.destruction")`).
  - Totmann mit unbrauchbarer Uhr (±∞, NaN) wie rückwärts: nichts (vernichtung-3). Jeder Schreibfehler an Zustand
    bzw. Ablage ist `io("destruction.write")` (vernichtung-5).
  - Prüfwerkzeuge (§21): Vernichtungs-Saaten, Ziel `vernichtung` mit eigenem Modell, Abbruch-Zeitpunkte in `ctaphid`,
    Einspielen in `sicherung`; DEBUG-Testhaken `TestHooks.afterDuressArgon`. `skripte/fuzz.sh` endet bei einem Fund
    mit Exit 1 (vorher ging der Wert in einer Subshell verloren).
- v4.6 (18.10.2026): Windows-Version, Etappe 1 (`windows/SPEC-WINDOWS.md`, Eintrag W1.1; geht §3, §16, §22 und §23
  vor). Der C#-Kern unter Windows schreibt dasselbe Format; neu ist nur die **Windows-Hello-Art** des
  Eintrags-Gerätefaktors (W4.1). Der Swift-Kern liest sie, schreibt sie unverändert weiter und behandelt sie als
  **anderes Gerät** (vorher: `corruptFile("payload.recoveryGroup")`, gemessen):
  - Inhalt, nur wenn unter Windows eingerichtet (jeder Mac-Inhalt bleibt bytegleich): `factors.windowsHello =
    {"keyID": UUID, "version": 1}` mit `factors.secureEnclave = null` (beide zugleich oder eine andere Version →
    `corruptFile("payload.factors")`); in jedem Siegel mit Gerätefaktor (Eintrag, Anker, vernichtbar) `"hello":
    {"salt": 32 B, "version": 1}` statt `"se"` (dann `"se": null`); V der Hello-Art `destruction.vKey = {"keyID",
    "windowsHello": 1}` ohne `publicKey` (sonst `corruptFile("payload.destruction")`). Die Inhaltsversion bleibt 2.
  - Maskenbit 0 zählt in beiden Arten (eingerichtete Faktoren, Maske eines Siegels). `checkSealing` verlangt zusätzlich,
    dass die Art jedes Siegels zum eingerichteten Schlüssel passt (Mac-Art ⇔ `se`, Hello ⇔ `hello`; vernichtbar nach
    der Art von V; sonst `payload.recoveryGroup` bzw. `entry.sealedState`); V und die Ablage des Vernichtungs-Passworts
    heissen nie wie der Eintrags-Gerätefaktor – in beiden Arten (`checkDestruction`).
  - Auf dem Mac: Aufdecken eines Siegels der Hello-Art → `factorUnavailable(.secureEnclave)` **ohne Provider-Aufruf**
    (auch ohne Provider); Versiegeln an den Hello-Schlüssel bzw. an ein V der Hello-Art → `factorUnavailable
    (.secureEnclave)`, nichts wird geschrieben (in Stufe 4/5 legt der Mac darum keine neuen Einträge an). Offene Felder
    ändern, umbenennen, löschen, wiederherstellen, Notfallweg und Neukodieren gehen und lassen die Hello-Teile
    unverändert. Ein Mac-Eintrags-SE-Schlüssel ersetzt den Hello-Schlüssel nur, solange keine Siegel daran hängen
    (sonst `notAllowedAtLevel`). Zusatz zu §22: `UnlockedVault.entryDeviceIsWindowsHello` (Hinweis in der Oberfläche).
  - Herausforderung und Ableitung rechnet nur Windows (`windows/src/Siegel.Core/KERN-NOTIZEN-CS.md`, W4.1).
  - Präzisiert §3 (gemessen, ohne Verhaltensänderung, bindend für jede weitere Umsetzung): `sortedKeys` sortiert ordinal
    nach UTF-8-Bytes; `/` immer als `\/`; Steuerzeichen als `\b \t \n \f \r`, sonst `\u00xx` klein; Zahlen in Swifts
    kürzester Form ohne `.0`; Wahlfelder als `null` (ausser `destruction`, das fehlt, wenn nichts eingerichtet ist).
    Beim Lesen gilt bei doppelten Schlüsseln der erste.
  - Beweise: `Tests/SiegelCoreTests/Interop/CSharpFixtureTests.swift` (C#-Dateien `cs_v2_stufe_a.siegel`,
    `cs_v2_beispiel.siegel`, `cs_v2_hello.siegel`, `cs_inhalt_hello.json` bytegleich neu kodiert, die vom Swift-Kern
    weitergeschriebene `swift_hello_aus_cs.siegel`, die C# wieder ganz aufdeckt), `KernWindowsHelloTests` (Mischformen,
    v4.5-Inhalt bytegleich, Versiegeln verweigert, Ersetzen des Schlüssels); `referenz/gegenprobe.sh` liest die C#-Dateien.
  - Grenze (bewusst): Ein Kern bis v4.5 hält einen Inhalt der Hello-Art für beschädigt – Windows-Tresore mit Windows Hello
    nur mit Mac-Versionen ab v4.6 austauschen. Verworfen: Inhaltsversion 3 für die Hello-Art (ältere Kerne meldeten dann
    `unsupportedVersion`, wären aber auch für Einträge ohne Gerätefaktor ganz ausgesperrt).
- v4.7 (18.10.2026): Normalisierung über beide Kerne gleich (Prüfung der Windows-Version, Befunde krypto-1, krypto-2,
  krypto-4; `windows/SPEC-WINDOWS.md` W12 W1.2).
  - §1.6: Die Master-Passwort-Regel verlangt Zeichen aus Unicode 15.0 (`MasterPasswordPolicy.unicodeVersion`, Age ≤ 15.0).
    Grund (gemessen auf macOS 26.7): Foundation kennt Unicode 16 nur zum Teil – `precomposedStringWithCanonicalMapping`
    lässt U+16D67 U+16D67 (Kirat Rai) und U+105D2 U+0307 (Todhri) stehen, setzt aber U+1611E U+1611E (Gurung Khema) zu
    U+16121 zusammen; ICU 76 setzt alle drei zusammen, ältere ICU keines. Ein Passwort mit solchen Zeichen ergäbe je nach
    System andere Argon2-Bytes, und ein späteres macOS mit vollständigen Unicode-16-Daten sperrte den Tresor auf dem Mac
    selbst aus. Für Zeichen aus Unicode 15.0 ist die NFC nach der Stabilitätsregel der Norm in jeder späteren Version
    gleich; `windows/skripte/listen_exportieren.py` prüft, dass Foundation dort die Daten der Norm hat. Bestehende Tresore
    öffnen weiter (beim Öffnen keine Prüfung); neue Passwörter mit späteren Zeichen lehnt `create`/`changeMasterPassword`/
    `recover` mit `passwordTooWeak` ab. Eintragspasswörter bleiben frei (sie gehen in kein Argon2; reuseTag und Master-Tag
    rechnen beide Kerne gleich).
  - §1.1 präzisiert (gemessen, ohne Verhaltensänderung auf dem Mac): Foundation weicht für einige Folgen von der Norm ab
    (Hangul nur aus Jamo mit eigenen Bereichen, fertige Silben bleiben; U+0CCA und Unicode-16-Zeichen wie U+113C5 werden
    in NFC nicht zerlegt; kein Ordnen über ein zerlegtes U+0F73 hinweg; Paar-Suche mit den unteren 16 Bit des Starters
    bei einem zweiten Glied aus der BMP; Doppelformen nach Nicht-Starter am Anfang). Diese Abweichungen sind Verhalten,
    keine Unicode-Version, und hängen nicht an der Regel oben. Der C#-Kern bildet sie genau nach; Beweis: Korpus Swift ↔ C#
    (`windows/tests/Siegel.Core.Tests/Werkzeuge/Daten/nfc_*`, 69 000 Fälle, dazu 800 000 Zufallsfolgen einmalig geprüft).
  - Beweise: `MasterPasswordPolicyTests.nurZeichenAusUnicode15`, `Tests/SiegelCoreTests/Interop/SwiftUnicodeFixtureTests.swift`
    (eingefrorene Swift-Tresore mit U+FFFE und Unicode-16-Zeichen in `windows/tests/Fixtures/`, die auch C# öffnet).
- v4.8 (18.10.2026): Robustheits-Befunde der Prüfung der Windows-Version (`windows/SPEC-WINDOWS.md` W12 W1.3), soweit
  sie beide Kerne betreffen (geht §3, §8 und §22 vor):
  - Inhalt (robust-8): **jede Eintrags-Kennung höchstens einmal**; jede doppelte `id` in `entries` ist
    `corruptFile("payload.duplicateID")`, auch ohne `meta`/`sealed` (bisher nur, wenn schon ein früherer Eintrag mit
    dieser Kennung Schutzdaten hatte). Grund: Gelesen wurden zwei Einträge mit gleicher Kennung, beim Speichern bekamen
    aber beide `meta` (`prepareEntryData` setzt es für jeden offenen Eintrag), und die eigene Rücklese-Prüfung lehnte die
    neue Datei immer ab (`io("save.verify")`): Der Tresor liess sich öffnen, aber nie mehr speichern. Kein Kern schreibt
    doppelte Kennungen (`upsert` sucht nach der Kennung, `importEntries` vergibt neue); erreichbar nur über einen
    fehlerhaften fremden Schreiber mit dem DEK. Verworfen: „der erste gilt“ (stiller Datenverlust, und vor
    `prepareEntryData` nötig).
  - CSV (robust-7): Spaltennamen über 256 Byte UTF-8 (ohne Leerraum am Rand) werden weder klein geschrieben noch
    verglichen; sie haben keine Rolle und kommen nur als „Spalte: Wert“ in die Notizen. Grund: Das kanonische Vergleichen
    (`Set<String>`) langer Folgen von Kombinationszeichen ist quadratisch (gemessen: 256 000 Zeichen 4,9 s auf dem Mac,
    eine 16-MiB-Kopfzeile etwa 1,4 h; im C#-Kern etwa 6-mal langsamer). Die Grenze gilt für die Bytes vor dem Vergleich:
    kanonisch gleiche Namen mit 255 und 256 Byte sind doppelt, mit 257 Byte nicht.
  - Gemessen und festgehalten (ohne Verhaltensänderung auf dem Mac, vom C#-Kern nachgebildet): Foundation liefert für
    einen Host über 2048 Byte UTF-8 kein `URLComponents.host` (mit Nicht-ASCII auch kein `URL.host`), ausser er war
    prozentkodiert (dann ohne IDNA dekodiert); `String.contains("://")` trifft nur an Character-Grenzen (in
    „https://“ + U+200D + „.ch“ nicht). Beweise: `Tests/SiegelCoreTests/Kern/KernRobustBefundeTests.swift`.
- Verworfen: **X-Wing** (CryptoKit `XWingMLKEM768X25519` / libsodium `crypto_kem_xwing`). Einfacher, aber nur
  ML-KEM-768 (Stufe 3); für Daten, die heute gestohlen und über Jahrzehnte aufbewahrt werden, bewusst
  ML-KEM-1024. Der Mehraufwand ist ein SHA3-Aufruf.
- Verworfen: `ptrace(PT_DENY_ATTACH)`: in Swift nicht direkt verfügbar, Nutzen null neben Hardened Runtime
  ohne `get-task-allow`; Absturzberichte entstehen mit wie ohne.
- Verworfen: Signatur mit Apple-Development-Identität: Der Sandbox-Container hängt an der Bundle-ID, nicht an
  der Signatur (gemessen); die Identität würde nur private Zertifikatsdaten in die App schreiben. Erst nötig,
  wenn Schlüsselbund/Touch ID dazukommen.
- Verworfen: PDF-Knopf fürs Notfallkit (Code allein öffnet den Tresor; PDF landet leicht in iCloud).
- Verworfen: CSV-Export mit Formel-Präfix `'` (OWASP-Rezept): würde Passwörter beim Import in andere Manager
  verfälschen; stattdessen roh, alle Felder zitiert, Warnung, und der Generator beginnt nie mit `= + - @`.
- Verworfen: Versuchsgrenzen/Selbstlöschung: schützen nicht gegen Offline-Angriffe, schaffen aber Aussperrung.
- Verworfen: Downloads von Wortlisten (zxcvbn, EFF) beim Bauen: Listen werden im Projekt gepflegt.

## 13. Härtestufe (v4): Sicherheitsstufen und Faktoren

Jeder Faktor liefert beim Entsperren 32 geheime Bytes, die in den Schlüssel eingehen. Fehlt einer, entsteht ein
falscher Schlüssel (keine „Tür in der Oberfläche“). Die Stufe legt Faktoren (kryptografisch, im KOPF) und Regeln
(Oberfläche, im verschlüsselten Inhalt) fest.

| Stufe | Faktoren (KOPF) | KDF | Notfall | Regeln (Inhalt) |
|---|---|---|---|---|
| 1 Standard | Passwort | Standard | ein Code | wie bisher |
| 2 Erhöht | Passwort + Secure Enclave (Touch ID) | Standard | ein Code | wie bisher |
| 3 Hoch | Passwort + Secure Enclave | Stark | ein Code | Touch ID vor jedem Aufdecken/Kopieren (Oberfläche), Sperre beim App-Wechsel (eine eben kopierte Zwischenablage bleibt bis zu ihrem Ablauf), Zwischenablage 15 s, Auto-Sperre höchstens 2 Min |
| 4 Maximal | Passwort + Secure Enclave + QR-Karte | Stark | **2 aus 3 Teilen** | wie 3 + neue Einträge standardmässig **Schutz 2** (§16), kein CSV-/KeePass-Export |
| 5 Festung | Passwort + Secure Enclave + QR-Karte + Sicherheitsschlüssel (FIDO2) | Stark | 2 aus 3 Teilen | wie 4 |

- Stufenwechsel (auf- und abwärts) braucht **alle Faktoren der aktuellen Stufe** und das Master-Passwort, erneuert
  DEK und KDF-Salz (§1.2) und schreibt sofort. Abwärts entfernt die zugehörigen Hardware-Schlüssel erst nach
  erfolgreichem Schreiben.
- Ehrlich in der Oberfläche: Jede Stufe zeigt eine Übersicht „Was du zum Öffnen brauchst / was im Notfall“.
- Stufe 5 ist auswählbar, solange kein Sicherheitsschlüssel angeschlossen ist, aber das Einrichten verlangt einen;
  der FIDO2-Code trägt den Hinweis „mit echter Hardware ungetestet“, bis ein Test mit Gerät in PRUEFLISTE.md abgehakt ist.

### 13.1 Ableitung (Format v2)

- `p = Argon2id13(pw, kdfSalt, t, m, 32)` (wie §1.1)
- `e = HKDF-SHA512(ECDH_SE, salt = vaultID, info = "Siegel v2 factor secure-enclave", 32)`
- `c = HKDF-SHA512(q, salt = vaultID, info = "Siegel v2 factor card", 32)`
- `y = HKDF-SHA512(hmacSecretOutput, salt = vaultID, info = "Siegel v2 factor fido2", 32)`
- `KEK_pw = HKDF-SHA512(ikm = p ‖ [e] ‖ [c] ‖ [y] (in dieser Reihenfolge, nur vorhandene), salt = kdfSalt,
  info = "Siegel v2 kek" ‖ factorMask (1 Byte), 32)`
- Fehlt ein Faktor-Geheimnis, das die Maske verlangt → `factorMissing(kind)` vor jeder Rechnung. Ein falsches
  Faktor-Geheimnis ist von einem falschen Passwort nicht unterscheidbar → `wrongPassword` mit Text „Passwort oder
  ein Faktor stimmt nicht“ (ausser bei der Karte: Karten-Kennung §14 erkennt die falsche Karte vorher).

### 13.2 Dateiformat Version 2

KOPF v2 (variable Länge wegen FIDO2-Credential), Little-Endian, strenger Parser:

| Feld | Grösse |
|---|---|
| magic `"SIEGEL"` | 6 |
| formatVersion `u16` = 2 | 2 |
| vaultID | 16 |
| kdfAlg `u8` = 1 | 1 |
| kdfOpsLimit `u32` | 4 |
| kdfMemLimit `u64` | 8 |
| kdfSalt | 16 |
| factorMask `u8` (Bit 0 = Secure Enclave, Bit 1 = Karte, Bit 2 = FIDO2; andere Bits → `corruptFile`) | 1 |
| recoveryScheme `u8` (1 = ein Code, 2 = Shamir 2 aus 3; anderes → `corruptFile`) | 1 |
| seKeyID (16 Nullbytes, wenn Bit 0 nicht gesetzt) | 16 |
| cardTag (4 Nullbytes, wenn Bit 1 nicht gesetzt) | 4 |
| fidoCredentialLength `u16` (0 wenn Bit 2 nicht gesetzt; sonst 16…1024) | 2 |
| fidoCredentialID | variabel |
| fidoSalt (32 Nullbytes, wenn Bit 2 nicht gesetzt) | 32 |
| recoveryPKM | 1568 |
| recoveryPKX | 32 |

SLOTS, INHALT, PRÜFSUMME wie v1; die Labels `"Siegel v1 …"` heissen in v2 `"Siegel v2 …"` (slot pw, slot rec,
payload, file check, hybrid KEM). Was zum gedruckten Kit gehört, bleibt in allen Versionen `"Siegel v1 …"`
(recovery checksum, kit id und die HKDF-Infos für R), damit gedruckte Codes und Kits gültig bleiben (v4.1).
Konsistenzregeln (Maske ↔ Nullfelder) verletzt → `corruptFile`. v1-Dateien bleiben lesbar (Fixture
`v1_beispiel.siegel`); jedes Speichern schreibt v2 nach angehefteter Sicherung `vor-migration-v1`.

### 13.3 Kopf-Auskunft ohne Geheimnis

`VaultStore.inspect() throws -> VaultHeaderInfo` liest nur KOPF + Prüfsumme (kein Argon2): formatVersion, vaultID,
factorMask, recoveryScheme, seKeyID, cardTag, fidoCredentialID, fidoSalt, kdf, kitID. Damit weiss die Oberfläche vor
dem Entsperren, welche Faktoren sie einsammeln muss.

## 14. Faktoren im Einzelnen (Modul `SiegelHardware`)

### 14.1 Secure Enclave (Touch ID)

- CryptoKit `SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl:)` mit
  `SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet])`.
  Funktioniert ad-hoc signiert ohne Schlüsselbund-Entitlement (gemessen); kein Data-Protection-Keychain (bräuchte
  ein Team-Profil, das beim kostenlosen Konto alle 7 Tage abläuft).
- Einrichten: SE-Schlüssel erzeugen; Software-Schlüssel `d` erzeugen; `P = d.publicKey`;
  `ECDH_SE = d.sharedSecretFromKeyAgreement(with: se.publicKey)`; `d` sofort verwerfen. Danach **einmal mit Touch ID
  prüfen**: `se.sharedSecretFromKeyAgreement(with: P)` muss dasselbe ergeben, sonst Abbruch.
- Ablage **nicht in der Tresordatei**: `Application Support/Siegel/Hardware/<seKeyID>.siegelhw` (0600) mit
  `{version, seBlob (dataRepresentation), P (x963)}`. So nützt eine gestohlene Datei oder Sicherung auch einem
  künftigen Quantenangreifer nichts (der öffentliche SE-Schlüssel steckt im Blob).
- Entsperren: `SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation:authenticationContext:)` mit frischem
  `LAContext` (`localizedReason` „Siegel entsperren“, `touchIDAuthenticationAllowableReuseDuration = 0`),
  ECDH mit P, danach `context.invalidate()`.
- Fehlerfälle: Blob fehlt / Biometrie geändert (`.biometryCurrentSet` macht den Schlüssel ungültig) → `factorUnavailable(.secureEnclave)`
  → Oberfläche bietet den Notfallweg. Abbruch durch Nutzer → `factorCancelled`. Touch ID nach zu vielen Fehlversuchen
  gesperrt bzw. Sensor nicht erreichbar (Deckel zu, Tastatur mit Touch ID nicht verbunden) →
  `factorTemporarilyUnavailable(.secureEnclave, "se.lockout"/"se.notReachable")` → erneut versuchen, **kein**
  Notfallweg (v4.4, §12); ist der Grund nicht erkennbar, entscheidet der Zustand von Touch ID ohne Dialog.
- Ehrliche Grenze (SICHERHEIT.md): Die Secure Enclave kann nur P-256. Ein künftiger Quantenangreifer mit der ganzen
  Festplatte (inkl. Blob) könnte `e` berechnen; dann bleibt der Schutz durch Passwort/Argon2 und die übrigen Faktoren.

### 14.2 QR-Schlüsselkarte

- `q` = 32 Zufallsbytes. `cardTag = SHA3-256("Siegel v2 card tag" ‖ vaultID ‖ q)[0..<4]` steht im KOPF (erkennt die
  falsche Karte, bevor gerechnet wird; 32 Bit verraten über 256-Bit-`q` nichts Nutzbares).
- QR-Inhalt: `SIEGELKARTE1:` + Crockford-Base32(q ‖ Prüfsumme 2 B) (Prüfsumme = `SHA3-256("Siegel v2 card checksum" ‖ q)[0..<2]`),
  Fehlerkorrektur-Stufe M, erzeugt mit CoreImage `CIQRCodeGenerator`. Darunter derselbe Code in Gruppen zum
  Abtippen (Notlösung bei defekter Kamera).
- Karte drucken wie Notfallkit (§7.6: ohne Vorschau, Druckerwarnung, `jobTitle "Dokument"`), Hinweistext: „Diese Karte
  ist ein Schlüssel. Getrennt vom Mac aufbewahren. Nicht fotografieren.“ Nach dem Drucken: Karte einmal scannen
  (Bestätigung), erst dann wird geschrieben.
- Scannen: `AVCaptureSession` (eingebaute Kamera) + `AVCaptureVideoDataOutput` + Vision `VNDetectBarcodesRequest`
  (nur `.qr`), Vorschau im eigenen Fenster (WindowGuard). Bilder nie speichern, Sitzung sofort nach Erkennung stoppen,
  beim Sperren stoppen. Entitlement `com.apple.security.device.camera`, `NSCameraUsageDescription`.

### 14.3 Sicherheitsschlüssel (FIDO2 hmac-secret)

- Eigene CTAP2-Umsetzung über USB-HID (FIDO-Usage-Page 0xF1D0): CTAPHID (INIT, CBOR, KEEPALIVE, ERROR, Zerlegung in
  64-Byte-Pakete), minimaler CBOR-Kodierer/-Dekodierer (strikt, Tiefen- und Längengrenzen – Daten vom USB-Gerät sind
  Angriffsfläche), `authenticatorGetInfo`, `authenticatorClientPIN` getKeyAgreement, PIN/UV-Protokoll 2 (bevorzugt)
  und 1, `authenticatorMakeCredential` (rp.id `"siegel"`, `hmac-secret: true`, nicht resident, `up` ja, `uv` nein),
  `authenticatorGetAssertion` mit `hmac-secret` (saltEnc/saltAuth), Ausgabe entschlüsseln. Geräte mit gesetzter PIN:
  hmac-secret ohne UV ist erlaubt; verlangt das Gerät UV → Fehler `factorUnavailable(.securityKey)` mit Hinweis.
  Anderer oder zurückgesetzter Schlüssel (0x2E) → `wrongSecurityKey`; belegt → `factorTemporarilyUnavailable(.securityKey,
  "fido.busy")`; Abbruch der Oberfläche über `SecurityKeyCancellation` → CTAPHID_CANCEL, `factorCancelled` (v4.4).
- KOPF speichert credentialID und fidoSalt (nicht geheim). Ausgabe `hmacSecretOutput` (32 B) → `y`.
- `VirtualAuthenticator` (nur Tests) setzt die Gegenseite nach CTAP 2.1 um; alle Abläufe werden dagegen getestet,
  zusätzlich Fuzzing des CBOR-/CTAPHID-Parsers.
- Entitlement `com.apple.security.device.usb`.

## 15. Notfallcode geteilt (Shamir 2 aus 3, Stufen 4/5)

- `R` wird über GF(2^8) (Reduktionspolynom 0x11B) byteweise geteilt: `share_x[i] = R[i] ⊕ a[i]·x` mit zufälligem `a`
  (32 B, `randombytes_buf`), x ∈ {1, 2, 3}. Multiplikation ohne Tabellen (zeitkonstant). Rekonstruktion per Lagrange in 0.
- Jeder Teil: `x (1 B) ‖ share (32 B) ‖ Prüfsumme 2 B` (`SHA3-256("Siegel v2 share checksum" ‖ x ‖ share)[0..<2]`),
  Crockford-Base32, Gruppen à 5, Kit-Kennung dazu, gedruckt als eigenes Blatt „Teil x von 3“.
- Wiederherstellung: zwei Teile eingeben → `R` → wie §1.3. Korrektur: `?` und 1–2 Fehler pro Teil; Kandidaten erst
  per Teil-Prüfsumme filtern, dann zusammen mit dem anderen Teil per pk-Vergleich bestätigen.
- `recoveryScheme` im KOPF sagt der Oberfläche, ob ein Code oder zwei Teile verlangt werden.

## 16. Eintrags-Schutz (Schutz pro Eintrag, ersetzt die „Einzelfreigabe“)

Zwei Ebenen: Die **Tresor-Stufe** (§13) bestimmt, was zum Öffnen des Tresors nötig ist (Liste, Titel, Benutzernamen).
Der **Eintrags-Schutz** bestimmt pro Eintrag, was zusätzlich nötig ist, um **dessen Geheimteile** (Passwort,
Notizen, Verlauf, TOTP) aufzudecken, zu kopieren oder zu bearbeiten – kryptografisch erzwungen, nicht nur in der
Oberfläche.

| Schutz | Pro Aufdecken zusätzlich nötig | Regeln |
|---|---|---|
| 1 Normal | nichts (Tresor offen genügt) | wie Tresor |
| 2 Fingerabdruck | Touch ID | – |
| 3 Hoch | Touch ID | Zwischenablage höchstens 15 s, nie Autofill |
| 4 Maximal | Touch ID + QR-Karte scannen | wie 3, nicht in CSV/KeePass-Export |
| 5 Festung | Touch ID + QR-Karte + Sicherheitsschlüssel berühren | wie 4 |

- Standard für neue Einträge: Tresor-Stufe 1–3 → Schutz 1; Tresor-Stufe 4/5 → Schutz 2. Einstellbar im Eintrag
  (Auswahl 1–5 mit kurzer Erklärung) und als Vorgabe in den Einstellungen.
- Ein Schutz verlangt, dass die nötigen Faktoren **für den Tresor eingerichtet** sind (unabhängig davon, ob sie zum
  Öffnen nötig sind): `enrolledFactors`. Fehlt einer → `factorMissing(kind)`; die Oberfläche bietet das Einrichten an.
  Pro Tresor gibt es höchstens einen Entsperr-SE-Schlüssel, einen Eintrags-SE-Schlüssel, eine Karte und einen
  Sicherheitsschlüssel; dieselbe Karte bzw. derselbe Schlüssel dient dem Öffnen (falls die Tresor-Stufe es verlangt)
  und den Einträgen (domänengetrennt).

### 16.1 Kryptografie

Jeder Faktor hat für Einträge einen **öffentlichen Teil im verschlüsselten Inhalt**, damit Schreiben ohne Faktor
geht und nur Lesen den Faktor braucht:
- Secure Enclave: eigener Eintrags-SE-Schlüssel (§14.1-Muster), öffentlicher Schlüssel P-256 (65 B).
- Karte: aus `q` deterministisch ein Hybrid-Schlüsselpaar: `seed = HKDF(q, salt = vaultID, info = "Siegel v2 card
  entry ML-KEM-1024 seed", 64)`, `x = HKDF(q, …, info = "Siegel v2 card entry X25519", 32)` → `cardPKM`, `cardPKX`.
- Sicherheitsschlüssel: zweites hmac-secret-Salz `entrySalt` (≠ Entsperr-Salz) → Ausgabe `y2` → Hybrid-Schlüsselpaar
  wie bei der Karte (`info = "Siegel v2 fido entry …"`) → `fidoPKM`, `fidoPKX`.

Versiegeln eines Eintrags mit Schutz s ≥ 2 und Faktormaske M:
- `ss_se = HKDF(ECDH(k, seEntryPub), salt = entryID, info = "Siegel v2 entry se")` mit ephemerem `k` (Software)
- `ss_card` / `ss_fido` = hybride Kapselung (ML-KEM-1024 + X25519, Kombinierer wie §1.3, Label
  `"Siegel v2 entry card"` bzw. `"Siegel v2 entry fido"`, entryID in der Eingabe) an die jeweiligen öffentlichen Schlüssel
- `K = HKDF-SHA512(ikm = HKDF(DEK, salt = entryID, info = "Siegel v2 entry dek") ‖ [ss_se] ‖ [ss_card] ‖ [ss_fido],
  salt = entryID, info = "Siegel v2 entry key" ‖ s ‖ M, 32)` → das Passwort bleibt immer nötig.
- Geheimteil-JSON mit XChaCha20-Poly1305, AD = `"Siegel v2 entry" ‖ vaultID ‖ entryID ‖ s ‖ M`
  (Herabstufen der Schutz-Angabe macht das Entschlüsseln unmöglich).
- Zusätzlich `recoveryEnvelope` an `pkM`/`pkX` (Label `"Siegel v2 entry recovery"`): mit dem Notfallcode lesbar;
  die Wiederherstellung entsiegelt alles und setzt Tresor-Stufe und alle Einträge auf 1 (Hinweis in der Oberfläche).
- Aufdecken: frischer LAContext pro Eintrag, Karte für jeden Eintrag neu scannen, Sicherheitsschlüssel neu berühren;
  K und Zwischenwerte sofort nullen; nichts davon wird zwischengespeichert.

### 16.2 Ehrliche Grenzen (SICHERHEIT.md)

- Ein Angreifer mit Kernelrechten auf dem entsperrten Mac bekommt pro Berührung/Scan höchstens das, was der Nutzer
  damit freigibt (er kann aber die Anfrage gegen einen anderen Eintrag tauschen). Sieht er die Karte einmal im
  Kamerabild, kennt er `q` dauerhaft: Die Karte schützt vor Diebstahl und Zwang (getrennt aufbewahrt), nicht vor einem
  bereits übernommenen Mac.
- Secure Enclave = P-256 (klassisch); Karte und Sicherheitsschlüssel nutzen hybride Post-Quanten-Kapselung.

## 17. Offline-Sicherheitsbericht

- Beim Schreiben eines Eintrags speichert der Kern in den Metadaten: Stärke-Stufe (zxcvbn), `passwordChanged`,
  `reuseTag = crypto_generichash(key: HKDF(DEK, "Siegel v2 reuse tag"), OpaqueString(password))[0..<16]` (gleiche
  Abbildung wie §1.1, v4.4; bis v4.3 nur NFC), Master-Wiederverwendung.
  So funktioniert der Bericht auch bei geschützten Einträgen, ohne Geheimteile zu öffnen.
- `vault.securityReport() -> SecurityReport`: schwache, wiederverwendete (gleicher reuseTag), alte (> 365 Tage),
  gleich-wie-Master; ohne Netzwerk, kein Abgleich mit Leak-Datenbanken (bewusst).

## 18. TOTP (2FA-Codes)

- `VaultEntry.totp`: `otpauth://totp/…`-URI oder reines Base32-Geheimnis. RFC 6238 (SHA1/SHA256/SHA512, 6/8 Ziffern,
  Periode 30 s Standard, 15–120 erlaubt), RFC 4648 Base32 tolerant (Leerzeichen, Kleinbuchstaben, fehlendes Padding).
  Strenger URI-Parser mit Grenzen. Anzeige mit Restsekunden, Kopieren über SecretPasteboard.
- CSV-Import: Apple `OTPAuth` und Bitwarden `login_totp` landen jetzt in `totp` statt in den Notizen.
- SICHERHEIT.md: 2FA-Codes im selben Tresor heben die Unabhängigkeit des zweiten Faktors teilweise auf.

## 19. KeePass-Export (KDBX 4.1)

- Nur Stufen 1–3, mit Master-Passwort (+ Faktoren) und eigenem **Export-Passwort** (MasterPasswordPolicy).
- KDBX 4.1: äusserer Kopf (Cipher ChaCha20, Kompression keine, KDF Argon2id mit p = 1, m = 256 MiB, t = 3 – damit
  auch libsodium-kompatibel), HMAC-SHA256-Blockstrom, innerer Kopf (innerer Zufallsstrom ChaCha20 für geschützte
  Werte), KeePass-XML (Gruppe „Siegel“, Einträge mit Title/UserName/Password/URL/Notes/otp, Zeiten).
- Datei-Hygiene wie CSV-Export (§8: .noindex-Ordner, Rechte, iCloud abgelehnt).
- Prüfung: Python-Referenz liest die Datei unabhängig; manueller Gegentest mit KeePassXC in PRUEFLISTE.md.

## 20. Autofill (vorbereitet)

- `AutofillMatcher` im Kern: Treffer nur bei gleichem Host oder Unterdomain des gespeicherten Hosts (keine
  „Teil-Treffer“ über die registrierbare Domain hinaus; kleine eingebaute Liste öffentlicher Suffixe wie `co.uk`,
  `com.au`, `github.io`); `http` wird nie für einen `https`-Eintrag angeboten. Tests mit Phishing-Beispielen
  (`beispiel-bank.example.evil.com`, Punycode-Doppelgänger).
- Erweiterung (`Erweiterungen/SiegelAutofill/`, `ASCredentialProviderViewController`) und XcodeGen-Projekt liegen
  bei, werden mit `skripte/autofill_bauen.sh` nur mit **bezahltem** Apple-Entwicklerkonto (`SIEGEL_TEAM_ID`) gebaut.
  Gemessen: das kostenlose Team bekommt das Entitlement nicht. Ohne Signatur wird die Erweiterung nur kompiliert
  (`CODE_SIGNING_ALLOWED=NO`), um Fehler früh zu sehen. Stufen 4/5: Erweiterung sagt „nur in der App“.
- Oberfläche: Einstellungen erklären den Stand ehrlich.

## 21. Prüfwerkzeuge und Härtung des Baus

- **Fuzzer** `SiegelFuzz` (ausführbares Ziel, mutationsbasiert und strukturbewusst, mit `-sanitize=address`):
  Dateiformat v1/v2, Notfallcode/Teile, QR-Inhalt, CSV, TOTP-URI, CBOR/CTAPHID. `skripte/fuzz.sh <Minuten>`.
  Ziel: kein Absturz, kein Hänger, nie Erfolg bei manipulierten Dateien. (v4.2: weitere Ziele und Abdeckung, §12.)
- **Sanitizer-Läufe**: `skripte/sanitizer.sh` (`swift test --sanitize=address`, `--sanitize=thread`).
- **Python-Referenz** `referenz/siegel_referenz.py` (libsodium per ctypes, hashlib): liest v1 und v2 (mit Faktor-
  Geheimnissen als Hex-Eingabe), prüft Prüfsumme, öffnet den Passwortweg, entschlüsselt den Inhalt; liest KDBX-Exporte.
  Ein Test vergleicht Swift und Python an den Fixtures.
- **Selbstprüfung der Signatur** beim Start (`SecStaticCodeCheckValidityWithErrors`, strikt): ungültig → kein
  Entsperren, Meldung. Ehrlich: ad-hoc lässt sich neu signieren; schützt vor versehentlich beschädigten oder
  nachträglich veränderten Bündeln, nicht vor einem Angreifer mit Benutzerrechten. (v4.4: in `AppModel.production`
  als Erstes und synchron, `BlockReason.signatureInvalid`.)
- **CI**: `.github/workflows/tests.yml` (macOS-Runner, `swift test`), mit Hinweis auf benötigte Xcode-Version.
- Entitlements neu genau sechs: bisherige vier + `device.camera` + `device.usb`. build.sh prüft das.

## 22. Schnittstelle v4 (bindend, ergänzt §8)

Faktor-Werte zwischen den Modulen sind immer **roh** (ECDH_SE, q, hmacSecretOutput je 32 B); die HKDFs aus §13.1
rechnet nur der Kern.

```swift
// SiegelCore – gemeinsame Typen (Datei Sources/SiegelCore/Faktoren.swift, eingefroren wie Model.swift)
public enum FactorKind: UInt8, Sendable, CaseIterable, Codable { case secureEnclave = 1, card = 2, securityKey = 4 }
public struct FactorSet: OptionSet, Sendable, Hashable, Codable { public let rawValue: UInt8
    public static let secureEnclave, card, securityKey: FactorSet }
public enum RecoveryScheme: UInt8, Sendable, Codable { case single = 1, shamir2of3 = 2 }
public struct LevelPolicy: Sendable, Equatable {
    public let touchIDBeforeReveal, perEntryRelease, lockOnDeactivate: Bool
    public let clipboardSecondsMax: Int?, autoLockMinutesMax: Int?
    public let allowCSVExport, allowKeePassExport, autofillAllowed: Bool }
public enum SecurityLevel: Int, Codable, Sendable, CaseIterable, Comparable {
    case standard = 1, erhoeht, hoch, maximal, festung
    public var factors: FactorSet { get }; public var kdf: KDFParameters { get }
    public var recoveryScheme: RecoveryScheme { get }; public var policy: LevelPolicy { get }
    public var title: String { get }   // „Standard“, „Erhöht“, „Hoch“, „Maximal“, „Festung“ }
public final class FactorSecret: @unchecked Sendable {   // 32 B in sodium_malloc, genullt beim Freigeben
    public init(copying bytes: some ContiguousBytes) throws      // ≠ 32 B → crypto("factor.length")
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R }
public struct FactorSecrets: Sendable { public var secureEnclave, card, securityKey: FactorSecret?
    public init(secureEnclave: FactorSecret? = nil, card: FactorSecret? = nil, securityKey: FactorSecret? = nil) }
public struct SEEnrollment: Sendable { public let keyID: UUID; public let secret: FactorSecret; public init(...) }
public struct EntryKeyEnrollment: Sendable { public let keyID: UUID; public let publicKey: Data /* x963, 65 B */; public init(...) }
public struct CardEnrollment: Sendable { public let q: FactorSecret; public init(q:) }
public struct SecurityKeyEnrollment: Sendable { public let credentialID: Data; public let salt: Data; public let output: FactorSecret
    public let entrySalt: Data; public let entryOutput: FactorSecret; public init(...) }
public struct NewFactorMaterial: Sendable { public var secureEnclave: SEEnrollment?; public var entryKey: EntryKeyEnrollment?
    public var card: CardEnrollment?; public var securityKey: SecurityKeyEnrollment?; public init(...) }
public enum EntryProtection: Int, Codable, Sendable, CaseIterable, Comparable {
    case normal = 1, fingerabdruck, hoch, maximal, festung
    public var factors: FactorSet { get }; public var title: String { get } }
/// Liefert beim Aufdecken die Faktoren eines Eintrags (Oberfläche + SiegelHardware). Nur benötigte Methoden werden gerufen.
public protocol EntryFactorProvider: Sendable {
    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret   // Touch ID
    func cardSecret() async throws -> FactorSecret                                                      // Karte scannen (q roh)
    func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret                  // berühren
}
public struct VaultHeaderInfo: Sendable, Equatable {
    public let formatVersion: UInt16; public let vaultID: UUID; public let factors: FactorSet
    public let recoveryScheme: RecoveryScheme; public let seKeyID: UUID?; public let cardTag: Data?
    public let fidoCredentialID: Data?; public let fidoSalt: Data?; public let kdf: KDFParameters; public let kitID: String }
public struct EntrySecrets: Sendable { public var password, notes, totp: String; public var history: [PasswordHistoryItem] }  // geschwärzt
public struct SecurityReport: Sendable, Equatable { public let weak: [UUID]; public let reused: [[UUID]]
    public let old: [UUID]; public let sameAsMaster: [UUID]; public let total: Int }
public struct RecoveryShare: Sendable { public let index: Int /* 1…3 */; public let formatted: String; public let kitID: String }  // geschwärzt
```

Model.swift-Ergänzungen: `VaultEntry.totp: String` (Standard ""), `VaultEntry.protection: EntryProtection` (Standard `.normal`), `VaultEntry.secretsSealed: Bool` (nur der Kern setzt es;
bei true sind password/notes/totp leer und history leer), `PendingRecovery.scheme: RecoveryScheme`,
`PendingRecovery.shares: [RecoveryShare]` (leer bei `.single`), `PendingRecovery.shareConfirmationGroups: [Int]` (je
Teil ein Gruppenindex). Neue `SiegelError`-Fälle: `factorMissing(FactorKind)`, `factorUnavailable(FactorKind)`,
`factorCancelled`, `wrongCard`, `notAllowedAtLevel`, `totpInvalid(String)`; v4.4: `factorTemporarilyUnavailable(FactorKind,
String)` (Codes `se.lockout`, `se.notReachable`, `fido.busy`) und `wrongSecurityKey` (§12).

```swift
// SiegelCore – geänderte/neue Methoden
extension VaultStore {
    public static func inspect(fileAt url: URL) throws -> VaultHeaderInfo
    public func inspect() throws -> VaultHeaderInfo
    public var hardwareDirectory: URL { get }                                  // <directory>/Hardware
    public func unlock(masterPassword: String, factors: FactorSecrets) throws -> UnlockOutcome   // unlock(masterPassword:) = ohne Faktoren
    public func checkRecoveryShares(_ inputs: [String]) throws -> [RecoveryCodeMatch]           // genau 2 Teile
    public func recover(shares: [String], newMasterPassword: String, kdf: KDFParameters = .standard) throws -> UnlockedVault
    public func restoreBackup(_ backup: BackupInfo, masterPassword: String, factors: FactorSecrets) throws -> UnlockedVault
    public func restoreNewestReadableBackup(masterPassword: String, factors: FactorSecrets) throws -> (UnlockedVault, BackupInfo)
    public func importBackup(from url: URL, masterPassword: String, factors: FactorSecrets) throws -> UnlockedVault
}
extension UnlockedVault {
    public var level: SecurityLevel { get }; public var policy: LevelPolicy { get }; public var headerInfo: VaultHeaderInfo { get }
    public func verify(masterPassword: String, factors: FactorSecrets) -> Bool
    public func changeMasterPassword(current: String, new: String, factors: FactorSecrets, kdf: KDFParameters? = nil) throws
    public func prepareRecovery(masterPassword: String, factors: FactorSecrets, scheme: RecoveryScheme) throws -> PendingRecovery
    public func commitRecovery(_ pending: PendingRecovery, confirmation: [String]) throws   // .single: 2 Gruppen; .shamir2of3: 3 (je Teil eine)
    public func changeSecurityLevel(to level: SecurityLevel, masterPassword: String, currentFactors: FactorSecrets,
                                    newFactors: NewFactorMaterial, recovery: PendingRecovery?, recoveryConfirmation: [String]) throws
    public var enrolledFactors: FactorSet { get }                                            // für Einträge verfügbar
    public func enrollFactors(_ material: NewFactorMaterial, masterPassword: String, currentFactors: FactorSecrets) throws
    public func revealSecrets(id: UUID, factors: EntryFactorProvider?) async throws -> EntrySecrets   // Schutz ≥ 2: Provider Pflicht
    public func setProtection(_ protection: EntryProtection, id: UUID, secrets: EntrySecrets) throws  // versiegelt neu (Geheimteile vorher aufgedeckt)
    public func securityReport() -> SecurityReport
    public func exportCSV(toParent directory: URL, masterPassword: String, factors: FactorSecrets) throws -> URL
    public func exportKeePass(toParent directory: URL, masterPassword: String, factors: FactorSecrets, exportPassword: String) throws -> URL
}
public enum CardCode {          // reines Format, ohne Kamera
    public static func generate() -> FactorSecret
    public static func payload(for q: FactorSecret) -> String          // "SIEGELKARTE1:…"
    public static func groupedText(for q: FactorSecret) -> String
    public static func decode(_ scannedOrTyped: String) throws -> FactorSecret   // Prüfsumme; Fehler invalidRecoveryCodeFormat
    public static func tag(for q: FactorSecret, vaultID: UUID) -> Data }
public enum TOTP { public struct Parameters: Sendable, Equatable { … }
    public static func parse(_ uriOrSecret: String) throws -> Parameters
    public static func code(_ p: Parameters, at date: Date) -> (code: String, remaining: Int) }
public enum KeePassExport { public static func kdbx(_ items: [(VaultEntry, EntrySecrets)], password: String) throws -> Data }
public enum AutofillMatcher { public static func matches(entryURL: String, serviceIdentifier: String) -> Bool }

// SiegelHardware (neues Modul, abhängig von SiegelCore; Zielordner Sources/SiegelHardware)
public enum SecureEnclaveFactor {
    public static var isAvailable: Bool { get }
    public static func enroll(directory: URL) throws -> SEEnrollment                 // prüft einmal mit Touch ID
    public static func enrollEntryKey(directory: URL) throws -> EntryKeyEnrollment
    public static func secret(keyID: UUID, directory: URL, reason: String) throws -> FactorSecret   // Touch ID
    public static func sharedSecret(keyID: UUID, ephemeralPublicKey: Data, directory: URL, reason: String) throws -> FactorSecret  // Eintragsschlüssel, Touch ID
    public static func remove(keyID: UUID, directory: URL) throws }
public enum CardImage { public static func qr(payload: String, pixels: Int) -> CGImage? }
@MainActor public final class QRScanner {          // Kamera, nur im Speicher, stoppt nach Erkennung
    public static func authorization() -> AVAuthorizationStatus
    public static func requestAccess() async -> Bool
    public init(onPayload: @escaping @MainActor (String) -> Void)
    public func start() throws; public func stop(); public var previewLayer: CALayer { get } }
public struct SecurityKeyDevice: Sendable, Hashable { public let name: String /* Hersteller/Produkt */ }
public final class SecurityKeyCancellation: Sendable {    // v4.4: Abbruch durch die Oberfläche
    public init(); public func cancel(); public var isCancelled: Bool { get } }
public enum SecurityKeyFactor {
    public static func connectedDevices() -> [SecurityKeyDevice]
    public static func register(on device: SecurityKeyDevice, cancellation: SecurityKeyCancellation? = nil) throws -> SecurityKeyEnrollment       // 1x registrieren + 2 Ausgaben (Entsperr- und Eintrags-Salz), Berührung, 30 s Frist
    public static func secret(on device: SecurityKeyDevice, credentialID: Data, salt: Data,
                              cancellation: SecurityKeyCancellation? = nil) throws -> FactorSecret }
public enum CodeSignatureCheck { public static func mainBundleIsValid() -> Bool }
```

## 23. Selbstvernichtung (v4.3): Totmann-Schalter, Fehlversuch-Zähler, Vernichtungs-Passwort

Nur in Tresor-Stufe 4/5 einschaltbar, nur für **ausgewählte Einträge** mit Schutz 4/5 („vernichtbar“). Alle drei
Auslöser vernichten dasselbe: den **Vernichtungsschlüssel**. Ehrliche Grenzen stehen in der Oberfläche und in
SICHERHEIT.md: Wer die Festplatte vorher kopiert, umgeht Zähler und Totmann-Schalter; deshalb ist die Vernichtung
kryptografisch gebaut (der Schlüssel liegt nur in der Secure Enclave dieses Macs und braucht den Finger).

### 23.1 Kryptografie

- Eigener **Vernichtungs-SE-Schlüssel** `V` (wie §14.1: CryptoKit Secure Enclave, `.biometryCurrentSet`), Blob in
  `Hardware/<vKeyID>.siegelhw`, mit `isExcludedFromBackup = true` (keine Time-Machine-Kopie).
- Vernichtbare Einträge werden wie §16.1 versiegelt, aber: statt des Eintrags-SE-Schlüssels gilt `V`
  (`ss_v` per ECIES an `vPub`), und es gibt **keinen recoveryEnvelope** (sonst wäre die Vernichtung wirkungslos).
  Beim Markieren deutlich: „Für diesen Eintrag gibt es keinen Notfallweg.“
- **Vernichten** = Blob-Datei mit Zufallsbytes überschreiben, `F_FULLFSYNC`, löschen, Ordner `fsync`; danach
  `destroyedAt` im Zustand vermerken. Braucht keinen DEK (geht im gesperrten Zustand). Der Tresor und alle anderen
  Einträge bleiben unverändert; die vernichtbaren sind ab dann auch in jeder Sicherung unlesbar.
- Ehrliche Grenze: Auf einer SSD ohne FileVault kann der alte Blob physisch liegen bleiben; er ist aber nur mit der
  Secure Enclave **dieses** Macs **und** dem Finger nutzbar.

### 23.2 Auslöser

1. **Totmann-Schalter**: Frist D Tage (7–365) seit dem letzten erfolgreichen Entsperren mit dem echten
   Master-Passwort. Geprüft beim Start der App, beim Aktivieren und alle 10 Minuten, auch gesperrt. Abgelaufen →
   vernichten, bevor irgendetwas angezeigt wird. Uhr läuft rückwärts (jetzt < letztes Entsperren − 1 Tag) →
   nicht vernichten, aber Frist auch nicht verlängern. Auf dem Sperrbildschirm erscheint ab 25 % Restzeit dezent
   „Frist endet am …“ – nach einer Vernichtung nicht mehr (v4.4: sonst verriete die stehen gebliebene Frist eine
   Vernichtungs-Sitzung, der Totmann-Schalter löst dann ohnehin nicht mehr aus). Ehrlich: Läuft Siegel nie, wird auch nicht vernichtet (kein Hintergrunddienst; ein
   Anmeldehelfer bräuchte eine App-Gruppe und damit ein Team-Profil).
2. **Fehlversuch-Zähler**: N (10–100) falsche Entsperrversuche in Folge (nur `wrongPassword`; nicht `kdfFailed`,
   Abbrüche, fehlende Faktoren, nicht das Vernichtungs-Passwort). Erfolgreiches Entsperren setzt zurück. Ab N/2
   Warnung „Noch x Versuche bis zur Vernichtung“ (Schutz vor eigenen Tippfehlern ist wichtiger als Geheimhaltung des
   Zählers).
3. **Vernichtungs-Passwort**: zweites Passwort (MasterPasswordPolicy, muss sich vom Master-Passwort unterscheiden).
   Es **öffnet den Tresor scheinbar normal** und vernichtet vorher still die markierten Einträge:
   - `dSalt` (16 B), Argon2id mit denselben Parametern → `d`; aus `d` per HKDF ein Hybrid-Schlüsselpaar
     (ML-KEM-1024 + X25519, wie Karte §16.1, `info = "Siegel v2 duress …"`); der DEK ist an dessen öffentlichen
     Schlüssel gekapselt (`duressEnvelope`) und an die Faktoren der Stufe gebunden (F, v4.4). Bei jeder DEK-Rotation
     kapselt der Kern neu (kein Passwort nötig, F aus der Sitzung).
   - Ablage im Container (`Hardware/<UUID>.siegelhw`, gleiche Form/Grösse wie die anderen Blobs), nicht in der
     Tresordatei.
   - Entsperren mit eingeschaltetem Vernichtungs-Passwort rechnet **immer beide** Argon2 parallel (gleiche Dauer bei
     echtem und Vernichtungs-Passwort). Passt das Master-Passwort → normal. Passt das Vernichtungs-Passwort → zuerst
     vernichten (synchron), dann mit dem DEK aus dem duressEnvelope öffnen; die vernichteten Einträge werden in dieser
     Sitzung **nicht angezeigt**, nichts deutet auf die Vernichtung hin, der Totmann-Schalter wird nicht verlängert.
   - Die Faktoren der Stufe verlangt die Oberfläche wie sonst, und kryptografisch braucht der Vernichtungsweg sie auch
     (v4.4): ohne sie liefert das Vernichtungs-Passwort keinen DEK. Erkannt (und vernichtet) wird über den Prüfwert aus
     `d` allein.
- Nach einer Vernichtung sieht der Besitzer beim nächsten echten Entsperren: „n Einträge wurden vernichtet
  (Auslöser, Datum)“ mit „Entfernen“. Nach einer Vernichtungs-Sitzung erneuert dieses Entsperren zuerst den DEK (v4.4).

### 23.3 Einstellungen und Schnittstelle

- Einstellungen → Sicherheitsstufe → „Selbstvernichtung“ (nur Stufe 4/5): vernichtbare Einträge (Auswahl), Totmann an/aus +
  Tage, Zähler an/aus + N, Vernichtungs-Passwort setzen/ändern/entfernen. Jede Änderung verlangt Master-Passwort und alle
  Faktoren. Deutliche Warnungen, Bestätigung durch Eintippen von „VERNICHTEN“ beim Einschalten.
- Zustand (nicht geheim, im Container `Hardware/zustand.json`): letzte echte Entsperrung, Fehlversuche, Einstellungen,
  `destroyedAt`/Auslöser, nach einer Vernichtungs-Sitzung `rekeyPending` (v4.4). Massgeblich für die Einstellungen
  ist der verschlüsselte Inhalt; die Container-Kopie dient den Prüfungen im gesperrten Zustand.

```swift
public enum DestructionTrigger: String, Codable, Sendable { case deadman, failedAttempts, duressPassword }
public struct DestructionSettings: Codable, Sendable, Equatable {
    public var deadmanDays: Int?          // nil = aus; 7…365
    public var maxFailedAttempts: Int?    // nil = aus; 10…100
    public var duressEnabled: Bool
}
public struct DestructionStatus: Sendable, Equatable {
    public let settings: DestructionSettings
    public let lastGenuineUnlock: Date?
    public let failedAttempts: Int
    public let deadline: Date?
    public let destroyed: (trigger: DestructionTrigger, at: Date)?   // als zwei optionale Felder umsetzen
    public let keyConfigured: Bool                                   // v4.4: V eingerichtet oder vernichtet
}
extension VaultStore {
    public func destructionStatus() -> DestructionStatus
    public func checkDeadman(now: Date) throws -> Bool                // true = gerade vernichtet
}
extension UnlockedVault {
    public var isDuressSession: Bool { get }
    public var destroyedEntries: [UUID] { get }                       // nur in echter Sitzung gefüllt
    public func configureDestruction(_ s: DestructionSettings, duressPassword: String?, destructible: Set<UUID>,
                                     masterPassword: String, factors: FactorSecrets, vKey: EntryKeyEnrollment?) throws
    public func removeDestroyedEntries() throws
}
// UnlockOutcome bekommt keinen neuen Fall: eine Vernichtungs-Sitzung sieht nach aussen aus wie .unlocked.
// SiegelHardware: SecureEnclaveFactor.destroy(keyID:directory:) überschreibt und löscht den Blob.
```
