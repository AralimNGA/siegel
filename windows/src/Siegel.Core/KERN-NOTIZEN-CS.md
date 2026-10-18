# C#-Kern – Notizen (Stand nach Stufe B und Integration)

Stand 18.10.2026. **Stufe A** setzt die plattformneutralen Grundlagen des Swift-Kerns byte-genau in C# (.NET 10) um:
libsodium-Bindung, SecureBuffer, ML-KEM/SHA3 (BouncyCastle), HKDF (.NET), Normalisierung, KDF mit Grenzen,
Mehrfaktor-Ableitung §13.1, Faktor-Typen, Format v1 lesen / v2 lesen+schreiben, Slots, Inhalts-JSON (ganzes Schema
inkl. §16/§17/§23-Felder), Polster, Notfallcode (Format, Korrektur, Kit-Kennung), Hybrid-KEM-Kombinierer §1.3, CardCode,
Shamir 2 aus 3. **Stufe B** baut darauf die Tresor-Schicht wie VaultStore*.swift/UnlockedVault*.swift: `VaultStore` und
`UnlockedVault` (Schnittstelle SPEC §8/§22/§23.3 in C#-Form), Speichern nach §4 mit Windows-Primitiven, Sicherungen
(Namen, Ausdünnen, Anheften, zweiter Ort), Rollback-Wächter, Beschädigt-Pfad, Migration v1→v2, Stufen und
Faktor-Einrichtung, Eintrags-Versiegelung §16 (Mac-Art byte-genau; **Windows-Hello-Art neu**, Abschnitt unten), Bericht
§17, CSV/KeePass-Export, Selbstvernichtung §23 (zustand.json, Ablage des Vernichtungs-Passworts, Löschschicht).

`dotnet build && dotnet test` (Debug): 0 Warnungen, nach der Integration mit den echten Werkzeugen 548 Tests grün
(Kern, Tresor, Werkzeuge), ≈ 75 s auf dem M5 Max (echte Argon2-Profile seriell in der Sammlung `EchteProfile`).
`dotnet build -c Release` baut ebenfalls ohne Warnung; dort sind die Kern-Tests ausgeblendet (sie brauchen die
DEBUG-Testschalter wie Swift), ein übersprungener Hinweistest sagt das. Stand, Befehle und Interop-Übersicht:
`../../LIESMICH-WINDOWS.md`.

## Dateien (Stufe A)

| Datei | Inhalt (Swift-Gegenstück) |
|---|---|
| `Native/Libsodium.cs` | eigene `LibraryImport`-Bindung (cdecl): init, malloc/free/mprotect, memzero/memcmp, randombytes, crypto_pwhash, XChaCha20-Poly1305-IETF, sodium_pad/unpad, scalarmult(_base), generichash. Fehlt die DLL → `Crypto("sodium.init")` |
| `Kern/SecureBuffer.cs` | `SecureBuffer` (SafeHandle über sodium_malloc) + `Zufall` (`SecureBytes.swift`) |
| `Kern/Fehler.cs` | Fabrik für `SiegelException` mit den Swift-Codes |
| `Kern/Bytes.cs` | `Bytes`, `ByteWriter`, `ByteReader` (LE, streng) |
| `Kern/Hashes.cs` | `Sha3Hasher` (BouncyCastle), `Hkdf` (.NET HKDF-SHA512 → SecureBuffer), `Sha256Hash` |
| `Kern/Kdf.cs` | `KdfParameters` (öffentlich), `CoreEnvironment`, `KdfLimits` (+ DEBUG `Testing`), `Kdf`, `PasswordNormalizer` (`KDF.swift`) |
| `Kern/Clock.cs` | Zeit ↔ double exakt, `Canonical`, `Now` (`TestHooks.swift`: Clock) |
| `Kern/TestHooks.cs` | DEBUG: `ForceKdfFailure`, `KdfCounter`, `Now`, `LevelKdfOverride` (AsyncLocal) |
| `Kern/Aead.cs` | Wrap/Unwrap (72 B), Seal/Open (`AEAD.swift`) |
| `Kern/X25519.cs` | X25519 über libsodium |
| `Kern/RecoveryKem.cs` | `RecoveryPublicKeys`, `RecoveryEncapsulation`, `HybridPrivateKeys`, `RecoveryKem` inkl. Zusatzfeld-Varianten (`RecoveryKEM.swift`) |
| `Kern/RecoveryCodeCodec.cs` | Codec + `RecoveryCodeCorrection` (parallel) (`RecoveryCodeCodec.swift`) |
| `Kern/Shamir.cs` | `Gf256`, `Shamir` (split/combine/Format/Kandidaten/`SearchPair`) |
| `Kern/CardCode.cs` | `CardCode` (öffentlich) |
| `Kern/FactorKdf.cs` | `FactorKdf`, `EntryKeyDerivation`, `KekCache` (`FactorKDF.swift`) |
| `Kern/VaultFile.cs` | `FileFormat`, `HeaderFactorFields`, `VaultHeader`, `VaultSlots`, `VaultFile` (+ `Inspect`) |
| `Kern/VaultContent.cs` | Inhaltsmodell: `VaultContent`, Siegel-/Gruppen-/Meta-Typen, `EntryFactorKeys`, `DestructionSettings` (öffentlich), `DestructionConfig`; `CheckSealing`, `CheckDestruction`, `DestructionKeysAvoid`, Verlaufsregel, `PrepareForSave`, `ResetAfterRecovery` |
| `Kern/SwiftJson.cs` | `SwiftDouble`, `SecureJsonWriter`, kleiner JSON-Baum `JNode` + `JRead` (Swift-Leseregeln) |
| `Kern/PayloadCodec.cs` | JSON ↔ gepolsterter Klartext, alle DTO-Abbildungen von Hand (`VaultContent.swift`: ContentDTO …) |
| `Kern/VaultCrypto.cs` | `OpenedVault`, `VaultCrypto` (MakeSlots, BuildFile, DecryptPayload, OpenWithPassword/Recovery, **Rekey**), `MasterTag` |
| `Kern/RecoveryMatching.cs` | Kern von `checkRecoveryCode`/`checkRecoveryShares`/`combineShares` ohne Datei (`VaultStore+Notfall.swift`) |
| `Faktoren.cs` | öffentliche Typen §22 (`Faktoren.swift`) |
| `Notfall.cs` | `RecoveryCode`, `PendingRecovery`, `RecoveryCodeMatch` (aus `Model.swift`) |

## Abbildung Swift → C# (öffentlich)

- Namen in PascalCase, Akronyme nach .NET: `KDFParameters` → `KdfParameters` (record struct), `EntryFactorProvider` →
  `IEntryFactorProvider` (async mit `CancellationToken`), `kitID` → `KitId`, `seKeyID` → `SeKeyId` usw.
- `FactorSet` ist ein `[Flags] enum : byte` (None/SecureEnclave/Card/SecurityKey/All) mit `Contains(kind)`,
  `IsSupersetOf`, `Kinds()` (Ableitungsreihenfolge). `FactorKind` hat die Bitwerte 1/2/4.
- `RecoveryScheme.single` heisst **`SingleCode`** (CA1720 verbietet den Typnamen „Single“), `.shamir2of3` → `Shamir2Of3`.
- `SecurityLevel`/`EntryProtection` (letzteres eingefroren in Siegel.Modell): Eigenschaften als Erweiterungsmethoden
  (`Factors()`, `Kdf()`, `RecoveryScheme()`, `Policy()`, `Title()`, `ClipboardSecondsMax()` …). `LevelPolicy` wie
  Swift-Code (mit `DefaultEntryProtection`; `perEntryRelease` aus SPEC §22 gibt es auch in Swift nicht).
- `FactorSecret` ist `IDisposable` (`Copy(span)`, `Read(callback)`, `ConstantTimeEquals`); `FactorSecrets` ist eine
  Klasse mit setzbaren Eigenschaften und `Available`. Wem welcher Faktor gehört, entscheidet der Aufrufer (Dispose).
- `VaultHeaderInfo` mit `ReadOnlyMemory<byte>?` für cardTag/fidoCredentialID/fidoSalt und Wertgleichheit.
  **Falle:** `cond ? null : new ReadOnlyMemory<byte>(x)` ergibt über die implizite byte[]-Umwandlung ein *leeres, aber
  vorhandenes* Memory – darum die Hilfe `Optional(byte[]?)`.
- `RecoveryCodeMatch`: `Exact` bzw. `Corrected(formatted, positions)`, Wertgleichheit; `ToString()` geschwärzt.

## Fehler (SiegelException, eingefrorenes Modell)

- Detail-Codes exakt wie Swift (`"header.length"`, `"file.checksum"`, `"payload.json"`, `"rec.slot"` …).
- `factorMissing(kind)` → `Code = FactorMissing`, `Detail = kind.Code()` = `"secureEnclave"`/`"card"`/`"securityKey"`.
- `unsupportedVersion(n)` → `Detail = "n"` (Zahl als Text). `wrongRecoveryCode` → `CodeKit`/`VaultKit` gesetzt.
- Programmfehler/Grenzfälle, die Swift mit `precondition` beendet, werfen hier `Crypto("…")` (z. B. `mlkem.seedLength`,
  `secure.readonly`, `secure.disposed`, `argument.null`, `kdf.uiThread`, `header.fields`).
- `SiegelErrorCode` hat seit der Integration auch `FactorTemporarilyUnavailable` (v4.4, Detail `se.lockout`,
  `se.notReachable`, `fido.busy`) und `WrongSecurityKey` (in `Modell.cs` angehängt). Der Kern reicht sie vom Anbieter
  unverändert durch; erzeugen wird sie erst die Plattformschicht.
- Nach aussen nur SiegelException: BouncyCastle-`ArgumentException` (Modulus-Prüfung, Längen), .NET-`CryptographicException`
  (HKDF), `JsonException`/`InvalidOperationException` (JSON) und `ObjectDisposedException` (SafeHandle) werden auf feste
  Codes abgebildet. Kein `Console`/`Debug`/`Trace` in Siegel.Core: geprüft von `../../skripte/sperren_windows.sh` und bei
  jedem `dotnet test` von `KernHygieneTests`. Interne Ausnahmen, die nie nach aussen gelangen, sind dort je Datei
  freigegeben: `FileIO.ExistsException`, `HelloMaterialNeededException`, `CryptographicException` in `P256`.

## SecureBuffer – Regeln

- Zugriff nur über Leihen: `using var l = buf.Borrow();` (`l.Span`), schreibend nur auf Rechenflächen
  (`Scratch` → `BorrowWritable` → `Freeze`). Die Leihe hält eine SafeHandle-Referenz (paralleles Dispose gibt erst nach
  der Leihe frei). Spans können nicht in Lambdas: Muster „Scratch füllen, Freeze, bei Fehler Dispose“ (siehe `Hkdf`,
  `Aead.Unwrap`, `X25519.SharedSecret`). Gleiches gilt für den `Geheimpuffer` der Werkzeuge (`Lesen()`/`Schreiben()`,
  auch der TOTP-Schlüssel nur über `TotpParameters.LeiheSchluessel()`, Befund hygiene-1).
- Besitz: Wer einen SecureBuffer bekommt, gibt ihn frei (`using`). Ausnahmen sind dokumentiert: `KekCache` besitzt seine
  p-Werte, `FactorKdf.DeriveKek` liefert dem Aufrufer **immer eine Kopie**; `OpenedVault` besitzt DEK, Inhalt und
  Migrations-KEK; `VaultContent` besitzt den Grundschlüssel, `Clone()` kopiert ihn.
- Verwaltete Kopien sind kurz und werden genullt, wo es geht (ML-KEM-Seed für BouncyCastle, ssM, Symbolfelder des
  Codes, Base64-Zeichen des Grundschlüssels). Der JSON-entryKey wird gar nicht verwaltet dekodiert, sondern mit
  `JRead.SecretData` direkt in einen SecureBuffer (Befund hygiene-3); `JRead.Data` legt nur ein Feld genau der
  Ergebnisgrösse an. Keine ungekürzten Zwischenfelder: Treffer-Symbole der Korrektur entstehen direkt im Ergebnis
  (`SymbolsFromBytes(bytes, ziel)`, hygiene-6), mehrere Eingaben werden „alle oder keine“ geparst
  (`RecoveryMatching.ParseAllOrWipe`, hygiene-5). Dateien werden ohne FileStream-Puffer geschrieben
  (`FileIO.WriteOptions`, `BufferSize = 0`, hygiene-2), sonst bliebe jedes Write unter 4 KiB (z. B. der CSV-Export) als
  ungenullte Kopie im Puffer der BufferedFileStreamStrategy. Ehrliche Grenzen (für SICHERHEIT-WINDOWS.md):
  .NET-Strings der Einträge und des Passworts; die Base64-Form des entryKey als .NET-String im JNode-Baum (wie Swift);
  die BouncyCastle-Objekte der ML-KEM-Schlüssel (verwaltet, nicht nullbar); der Keccak-Zustand liegt kurz im
  verwalteten Speicher (DoFinal setzt ihn zurück).
- **Windows-Hinweis für Stufe B:** sodium_malloc sperrt unter Windows mit `VirtualLock` (Arbeitssatz-Grenze, Standard
  ≈ 200 Seiten); libsodium ignoriert ein Scheitern, die Puffer bleiben dann nur ungesperrt. Bei vielen gleichzeitigen
  Puffern (Byte-Kipp-Tests, Korrektur) ggf. `SetProcessWorkingSetSize` in der App erhöhen; im Kern nichts tun.

## Zeit (DateTimeOffset ↔ secondsSince1970)

- Modell (eingefroren) hat `DateTimeOffset` (100-ns-Ticks), Swift `Date` (double). `Clock.ToSeconds` = nächstes double
  zu Ticks/10^7 (über die korrekt rundende .NET-Zahlerkennung), `Clock.FromSeconds` = nächster Tick (exakt aus den Bits,
  halbe Ticks zur geraden Zahl). Für alle Zeiten nach 1987 ist double → Ticks → double bitgenau (Test mit 20 000
  Zufallswerten); dadurch kodiert C# Swift-Inhalte bytegleich neu.
- `Clock.Canonical` macht Zeitpunkte zum Fixpunkt (Gegenstück zu Swift `Clock.canonical`); `PrepareForSave` kanonisiert
  alle Zeiten. `UtcNow` direkt zu speichern wäre sonst nach dem Rundlauf um ±1–2 Ticks anders. Ausserhalb der Jahre
  1–9999 (Swift erlaubt das) → `corruptFile("payload.json")`.

## Inhalts-JSON – gemessenes Swift-Verhalten (macOS 26, 18.10.2026)

Geschrieben (`SecureJsonWriter`, Schlüssel von Hand in ordinaler Reihenfolge, ein Test prüft jedes Objekt):
- `.sortedKeys` sortiert **ordinal nach Bytes** (`"A" < "Z" < "_x" < "a" < "a10" < "a9"`), keine Leerzeichen.
- Escapes: `"` `\\` `\/` (Schrägstrich immer!), `\b \t \n \f \r`, übrige < 0x20 als `\u00xx` mit Kleinbuchstaben;
  DEL, U+2028/2029 und Nicht-ASCII roh in UTF-8. Data = Standard-Base64 mit `=`, darin `/` → `\/`.
- Zahlen = Swift `description` ohne „.0“: `1792000000`, `1792000000.123`, `-0`, `1e-07`, `1e+16`,
  `9.007199254740994e+15` (Exponentialform ab |x| > 2^53 oder Dezimalexponent < −3). `SwiftDouble` bildet das aus den
  kürzesten .NET-Ziffern („R“) nach.
- Nullwerte: alle Wahlfelder als `null`, ausser `destruction` (fehlt ganz, wenn nichts eingerichtet ist). UUID gross.
- Legacy v1 (nur Tests/Fixture-Nachbau): ohne level/factors/entryKey/recoveryGroups bzw. totp/protection/meta/sealed.

Gelesen (`JNode` + `JRead`, wie die Swift-`Decodable`):
- **Doppelte Schlüssel: der erste gilt** (gemessen, nicht abgelehnt); unbekannte Schlüssel werden übergangen.
- Int auch aus `1.0`/`1e0` (exakt ganz), sonst Fehler; UInt8-Bereich für `mask`; Datum aus Zahl (auch ganzzahlig).
- Data nur striktes Base64 (Länge % 4, Auffüllung, kein Leerraum); UUID nur 36 Zeichen (Gross/Klein egal).
- Einzelnes Surrogat (`\ud800`) oder rohes Steuerzeichen im String → Fehler; JSON-Kommentare/Kommas am Ende → Fehler.
- Reihenfolge der Prüfungen wie Swift: Strukturfehler `payload.json` → `payload.version` → `payload.factors` →
  `payload.entryKey` → `payload.duplicateID` (jede doppelte Kennung, v4.8) → `payload.destruction` → `CheckSealing` (`payload.recoveryGroup`,
  `payload.meta`, `entry.sealedState` …); danach in `DecryptPayload` `payload.level` und `payload.destruction`
  (`DestructionKeysAvoid`). Für `v < 2` werden level/factors/entryKey/recoveryGroups/destruction gar nicht gelesen.
- Die Mac-Fixture `v2_beispiel.siegel` stammt aus **Swift-Stufe A**: ohne `entryKey`, `meta`, `sealed`,
  `recoveryGroups` (wird gelesen; der Neukodier-Test vergleicht sie darum strukturell, v1 und alle heutigen
  Swift-Inhalte bytegenau).

## Kryptografie – Abweichungen und Entscheide

- **ML-KEM-1024 über BouncyCastle 2.7.0** (`MLKemPrivateKeyParameters.FromSeed`, `MLKemEncapsulator/Decapsulator`):
  `MLKemPublicKeyParameters.FromEncoding` prüft den Modulus sofort (CryptoKit erst beim Kapseln). Beobachtbar gleich:
  Kapseln an einen ungültigen pkM → `Crypto("kem.encapsulate")`; `PrivateKeys(…, expected)` → null. Entkapseln mit
  falschem Chiffrat → implizite Ablehnung (anderer Schlüssel, keine Ausnahme), wie FIPS 203/CryptoKit.
- Zufall fürs Kapseln: BouncyCastles Standard-`SecureRandom` (→ .NET `RandomNumberGenerator`, OS-CSPRNG); alles andere
  (Nonces, Salze, DEK, R, a, ephemere X25519) aus libsodium `randombytes_buf`.
- X25519 über libsodium `crypto_scalarmult(_base)`: lehnt Null-/Kleinordnungspunkte ab wie CryptoKit (Test).
- HKDF über `System.Security.Cryptography.HKDF` (leeres Salz = HashLen Nullbytes wie CryptoKit ohne `salt:`).
- UUID-Bytes in RFC-4122-Reihenfolge: `Guid.ToByteArray(bigEndian: true)` / `new Guid(span, bigEndian: true)`.
- RFC 8265: `PasswordNormalizer.Normalize` = `SwiftText.OpaqueString` (Zs aus der Swift-Tabelle → U+0020, dann NFC wie
  Foundation aus `swift_nfc.txt.gz`, Abschnitt „Normalisierung und Gleichheit“). Einzelne Surrogate (in Swift-Strings
  unmöglich) werden vorher U+FFFD – genau das, was UTF-8 daraus machen würde. Nie `string.Normalize` (Befunde
  krypto-1/krypto-2; die Grep-Sperre verbietet es).
- White_Space für Code-Eingaben als feste Menge (Unicode-Eigenschaft, stabil), nicht `char.IsWhiteSpace`.
- Argon2 auf dem Oberflächen-Thread: `CoreEnvironment.IsUiThread` setzt die App (WinUI: `DispatcherQueue.GetForCurrentThread()
  is not null`); dann `Crypto("kdf.uiThread")`. Ohne Wert keine Prüfung (Tests, Werkzeuge).
- Testschalter: `AsyncLocal` fliesst – anders als Swift `@TaskLocal` – in `Task.Run` und `Parallel.For` mit (Swift
  braucht dafür `TestHooks.Snapshot`; hier nicht nötig). Der KDF-Testbereich ist `KdfLimits.Testing` (nur DEBUG).

## Stufe B: Tresor-Schicht

### Dateien (Stufe B)

| Datei | Inhalt (Swift-Gegenstück) |
|---|---|
| `Kern/FileIO.cs` | Dateiprimitive W3: exklusiv anlegen (`CreateNew`, `WriteThrough`, `Flush(true)`), Lesen ohne Link-Folgen, `MoveFileExW`/`rename`, Ordner-ACL bzw. 0700, Ordner-fsync (Unix), Auflisten, Überschreiben-und-Löschen (`FileIO.swift`) |
| `Kern/Backups.cs` | `BackupNaming` (Namen, Gründe, Zeitstempel nachsichtig wie Foundation, extern `Siegel-<8 hex>-…`, Quarantäne `beschaedigt-…`), `BackupThinning` (`Backups.swift`) |
| `Kern/P256.cs` | P-256 über `ECDiffieHellman` (Mac-Art, ephemeres k, Ablage-Punkt) |
| `Kern/EntrySealing.cs` | §16.1/§23.1: Grundschlüssel, ss-Werte, K, AD, Versiegeln/Freigeben/Öffnen, Notfall-Umschlag, Gruppen + Anker + Kit-Umschlag, Geheimteil-JSON, reuseTag; `HelloSealing` + `HelloMaterialNeededException` (`EntrySealing.swift`) |
| `Kern/VaultContentSchutz.cs` | Versiegeln im Inhalt, Gruppen anlegen/aufräumen/umkapseln, Entsiegeln im Notfall, Schätzwerte (`VaultContent+Schutz.swift`) |
| `Kern/DestructionState.cs` | `DuressCrypto` (d, Prüfwert, F-Bindung, KEK), `DuressFile` (2048 B), `DestructionState` = `Hardware/zustand.json` (`DestructionState.swift`, `Selbstvernichtung.swift`) |
| `Kern/TestHooks.cs` | dazu `CorruptTempBeforeVerify`, `FreeSpaceOverride`, `FailPurgeBackups`, `AfterDuressArgon`, `KdfObserverHook`, `KdfRendezvous`, `CsvExporter`, `KeePassExporter` |
| `Tresor/Typen.cs` | öffentlich: `UnlockOutcome`, `IRollbackGuard` + `InMemoryRollbackGuard` + `FileRollbackGuard`, `BackupInfo`, `PurgeReport`, `SecondaryBackupResult`, `DestructionStatus`, `IDestructionKeyEraser` (+ `ClosureDestructionKeyEraser`, `FileDestructionKeyEraser`) |
| `Tresor/VaultStore.cs` | Store, `Persist` (§4 Schritte 0–7), Sicherungen, Ausdünnen, zweiter Ort, Export, Quarantäne, `PurgeBackups` (`VaultStore.swift`) |
| `Tresor/VaultStore.Zugang.cs` | `Create`, `Inspect`, `Unlock` (Totmann, Zähler, Vernichtungs-Passwort, Rotation danach), Restore/Import, neueste lesbare Sicherung, `Rekey` (`VaultStore+Zugang.swift`) |
| `Tresor/VaultStore.Notfall.cs` | Code/Teile prüfen (auch gegen eine gewählte Datei und gegen die Sicherungen), `Recover`, `RecoverBackup`, `RecoverFromNewestReadableBackup` (`VaultStore+Notfall.swift`) |
| `Tresor/VaultStore.Vernichtung.cs` | Stand, Totmann, Fehlversuche, Vermerke, Ablage, `ParallelKdf`, `SecretCache` (`VaultStore+Vernichtung.swift`) |
| `Tresor/UnlockedVault.cs` | Sitzung und Zustand, Einträge, Papierkorb, Import, Prüfen, Passwortwechsel, Export-Orte (`UnlockedVault.swift`) |
| `Tresor/UnlockedVault.Notfall.cs` | Kit vorbereiten/bestätigen, bestehendes Kit bestätigen, `PurgeBackups` (`UnlockedVault+Notfall.swift`) |
| `Tresor/UnlockedVault.Stufen.cs` | Faktoren einrichten, Stufe wechseln (`UnlockedVault+Stufen.swift`) |
| `Tresor/UnlockedVault.Schutz.cs` | Aufdecken, Schutz setzen, Hello-async-Varianten, Bericht §17, CSV/KeePass (`UnlockedVault+Schutz.swift`) |
| `Tresor/UnlockedVault.Vernichtung.cs` | Selbstvernichtung einrichten, vernichtete Einträge entfernen, Vernichtungs-Sitzung (`UnlockedVault+Vernichtung.swift`) |

### Abbildung Swift → C# (Tresor)

- **Synchron und threadsicher** wie SPEC §8/§22: alle Methoden blockieren (Argon2 im aufrufenden Thread; auf dem
  Oberflächen-Thread `Crypto("kdf.uiThread")`). Ein Schreib-Riegel je Sitzung (`WriteLock`, nie über ein `await`), ein
  Datei-Riegel und ein Vernichtungs-Riegel je Store. Wo Swift `async` ist (Faktoren über den Anbieter), heisst die
  C#-Methode `…Async` mit `CancellationToken`; der synchrone Kern läuft dann im Thread-Pool (`InBackground`), eine
  Absage wird `FactorCancelled` (nach aussen nur SiegelException).
- `unlock` → `UnlockOutcome` (Klasse statt enum mit Nutzlast): `Vault`, `IsRollbackSuspected`, `SeenGeneration`,
  `FileGeneration`. Bei Rollback-Verdacht ist die Sitzung offen; die Oberfläche entscheidet (wie Swift).
- Umbenannt: `destructionStatus()` → `GetDestructionStatus()` (sonst gleichnamig mit dem Typ), `readBackupInfo(url:)` →
  statisch `ReadBackupInfo(path)`, `vaultURL` → `VaultPath` (string), `hardwareKeyURL` → `HardwareKeyPath`,
  `backupRoot` → `BackupsDirectory`. `RecoveryScheme.single` heisst `SingleCode` (Stufe A).
- Nicht übernommen (gehört in die App): `defaultDirectory` (Windows: `%LOCALAPPDATA%\Siegel`), `volumeIsEncrypted`
  (BitLocker-Abfrage, W3).
- Rollback-Wächter: `IRollbackGuard` (Swift: Protokoll + UserDefaults). `FileRollbackGuard(path)` ist das
  Windows-Gegenstück: Textdatei „UUID Generation“ je Zeile, nur steigend, atomar ersetzt; kaputte Zeilen zählen nicht.
- Vernichtungsschlüssel löschen: `IDestructionKeyEraser` (Swift: Closure). Die App setzt die Plattform-Löschung
  (Windows Hello: `KeyCredentialManager.DeleteAsync`); ohne sie `FileDestructionKeyEraser` (überschreiben, löschen).
  Liegt die Datei nach der Schicht noch da, überschreibt und löscht der Kern sie selbst.
- Export-Orte: iCloud-Pfad (`/Library/Mobile Documents`) → `ExportLocationRejected("icloud")`; unter OneDrive
  (Umgebungsvariablen `OneDrive`, `OneDriveConsumer`, `OneDriveCommercial`) → `ExportLocationRejected("onedrive")`. Ordner
  `Siegel-Export-JJJJ-MM-TT[-n].noindex`, unter Windows mit `NotContentIndexed`.
- **Besitz**: `UnlockedVault` ist `IDisposable` (= `Lock()`). Der Sitzungszustand ist ein unveränderlicher `State` (Kopf,
  Slots, DEK, Inhalt, Tags, vorbereitetes Kit, F); jede Übernahme ersetzt ihn. Leser halten ihn über einen `Enter()`-Scope
  (Zähler); was ersetzt wurde, wird erst freigegeben, wenn kein Leser mehr darin ist (Ersatz für ARC). `Lock()` wartet
  nicht auf Leser, sie sehen danach `Io("vault.locked")`. `Entries` liefert Kopien. Vom Anbieter gelieferte
  `FactorSecret`s gehören dem Kern (er gibt sie frei); `CachingEntryFactors` gibt Kopien weiter.
- `Persist` arbeitet auf einer Kopie des Inhalts und liefert die gespeicherte Fassung; nach dem Schreiben wirft kein
  Schreibweg mehr (Befund datei-1: Sicherungen entfernen scheitert → Bericht `Interrupted`).

### Speichern unter Windows (W3)

- Ablauf §4 wie Swift: (0) Freiraum ≥ 64 MiB, Platte = erwarteter Stand (`VaultChangedOnDisk`), (1) Temp-Datei
  `.Tresor.siegel.<hex>.tmp` exklusiv, `WriteThrough` + `Flush(true)` (= `FlushFileBuffers`), (2) Rücklesen und Prüfen
  über den SHA-256-Digest aus `BuildFile`, (3) alte Datei als Sicherung klonen (lesen + exklusiv schreiben; kein APFS-Klon;
  eine unlesbare Datei gestreamt ohne Grössengrenze, robust-5), (4) `MoveFileExW(MOVEFILE_REPLACE_EXISTING |
  MOVEFILE_WRITE_THROUGH)` mit Pfaden wie .NET (`\\?\` ab 260 Zeichen, robust-6) und bis 2 s Wiederholung bei
  `ERROR_ACCESS_DENIED`/`ERROR_SHARING_VIOLATION` (Virenscanner, Indexer; robust-1) (sonst `rename`), (5) Ordner-fsync nur unter Unix
  (macOS `F_FULLFSYNC`), (6) Rollback-Wächter, (7) Ausdünnen, zweiter Ort höchstens stündlich. Temp-Reste älter als eine
  Minute räumt das erste Speichern auf.
- Rechte: jede neu angelegte Ordnerebene und jede Datei nur für den Benutzer (Windows: geschützte ACL FullControl für den
  Benutzer, im AppContainer die eigene Paket-SID und SYSTEM, ohne Vererbung von oben; Unix 0700/0600). Unter Windows
  bleibt die ACL bestehender Ordner unverändert (robust-4: sonst sperrte sich die App im AppContainer aus), unter Unix
  wird ein bestehender Zielordner wie in Swift auf 0700 gesetzt; `FileRollbackGuard` ändert seinen Elternordner nie. Symbolische Links werden nie gelesen oder aufgelistet (wie
  `O_NOFOLLOW`); ein gebrochener Link gilt als vorhanden (nichts schreibt darüber).
- Auf dem Mac laufen alle Tests mit denselben Klassen (die Windows-Zweige sind `OperatingSystem.IsWindows()`-Weichen).

### Normalisierung und Gleichheit (Befunde krypto-1, krypto-2, krypto-4; W1.2)

- **Warum nicht ICU**: `string.Normalize(FormC)` wirft bei U+FFFE (`ArgumentException`, Swift nimmt das Zeichen an) und
  hängt an der ICU des Systems: auf dem Mac setzt .NET (ICU 76) U+16D67 U+16D67 und U+105D2 U+0307 zusammen, Foundation
  nicht; ältere ICU unter Windows setzt dafür U+1611E U+1611E nicht zusammen, Foundation schon. Jede Abweichung heisst
  andere Argon2-Bytes → `WrongPassword` für den Tresor der Gegenseite.
- **Tabelle** `Siegel.Werkzeuge/Unicode/swift_nfc.txt.gz`, gemessen von `SiegelStaerkeExport nfc` (Swift, macOS 26.7) und
  geschrieben von `windows/skripte/listen_exportieren.py` (prüft dabei für jedes Zeichen aus Unicode 15.0 Zerlegung,
  Klasse und Paare gegen `unicodedata`): `D` Zerlegung (Foundation-NFD), `O` träge Zeichen, `C` Kombinationsklasse (an
  Vergleichszeichen gemessen), `K` eigene Klasse zerlegbarer Zeichen, `P` Paare (Schritt für Schritt aus Foundation-NFC
  abgeleitet), `SD`/`SC`/`SP`/`SX` Abweichungen der Standardbibliothek, `A` Alter ≤ 15.0.
- **Foundation-NFC** (`SwiftNormalisierung.NfcFoundation`; Master-Passwort, reuseTag, Master-Tag, alte reuseTag-Formel):
  zerlegen, ordnen, zusammensetzen wie UAX #15 – mit Foundations gemessenen Eigenheiten:
  1. **träge Zeichen** (Hangul-Silben, U+0CCA, U+113C5/7/8, U+16121–16128, U+16D68–16D6A): aus der Eingabe nicht zerlegt und
     nicht weiter zusammengesetzt (`U+AC00 U+11A8` bleibt; die Norm ergäbe U+AC01);
  2. **Hangul** nur aus direkt folgenden Jamo L V (T), mit Foundations Grenzen L ≤ U+1113, V ≤ U+1176, T U+11A7…U+11C3
     (U+11A7 verschwindet, Ergebnis im Surrogat-Bereich → U+FFFD);
  3. **Abschnitte**: ein zerlegter Starter wie U+0F73 beginnt einen Ordnungsabschnitt (kein Ordnen davor hinweg); beginnt
     er mit einem Nicht-Starter, setzt Foundation nichts mit dem Starter davor zusammen;
  4. **Paar-Suche** mit einem zweiten Glied aus der BMP über die unteren 16 Bit des Starters (U+F00D4 U+0301 → U+1ED0);
     ein Nicht-Starter ganz am Anfang dient als Starter (U+11F41 U+0301 → U+1F45);
  5. **Verdoppler** (U+1611E, U+113C2): nach einem Nicht-Starter am Anfang oder dem Ergebnis einer Einzelzerlegung
     (U+F928 → U+5ECA) entsteht die Doppelform (U+0301 U+1611E → U+16121).
  Beweis: Korpus `nfc_*` (69 000 Fälle, Swift-Werte) in `NormalisierungTests`, dazu einmalig 800 000 Zufallsfolgen ohne
  Abweichung (nicht eingecheckt). Unbekannte Eigenheiten fallen im Korpus auf, sobald `korpus_erzeugen.py` neu läuft.
- **Gleichheit wie Swift-`String`** (`SwiftStringComparer`, `SwiftText.KanonischGleich`): Swift vergleicht die NFC der
  Standardbibliothek (nicht Foundation): Hangul und Unicode 16 nach der Norm, Ordnungsabschnitte wie oben. Der Schlüssel
  ist diese NFC; zwei Strings sind gleich, wenn die Schlüssel ordinal gleich sind. **Regel: Strings, die Swift mit
  `==`, `Set` oder `Dictionary` vergleicht, vergleicht C# mit `SwiftStringComparer`, nie ordinal** – ohne die
  Zs-Abbildung aus §1.1 (Swift hält „a b“ mit U+00A0 und „a b“ für verschieden). Umgesetzt: Import (Doppel-Schlüssel
  Host + Benutzer, Passwort-Mengen), Verlaufsregel in `Upsert`, `SetProtection`, `ReplacingPassword`. Beweis: Korpus
  `gleich_*` (68 000 Paare, Swift `==`).
- **Master-Passwort-Regel** ab v4.7: nur Zeichen aus Unicode 15.0 (`SwiftNormalisierung.NurUnicode15`, Alter aus der
  Swift-Tabelle). Eintragspasswörter bleiben frei.

### Windows-Hello-Art des Eintrags-Gerätefaktors (W4.1) – Format, Version 1

Neue, versionierte Art neben der Mac-Art. Sie steht nur im Inhalt; fehlt sie, bleibt der Inhalt bytegleich zum
Swift-Kern. Ein Tresor hat genau eine Art (beide zugleich → beim Lesen `CorruptFile("payload.factors")`).

- **Schlüssel**: Windows-Hello-Schlüssel `Siegel-<vaultID>-<keyID>` (RSA 2048, `KeyCredentialManager`), kein
  öffentlicher Teil im Inhalt.
- **Inhalt** `factors.windowsHello = {"keyID": "<UUID>", "version": 1}`, dabei `factors.secureEnclave = null`. Schlüssel
  sortiert: `card`, `secureEnclave`, `securityKey`, `windowsHello`.
- **Siegel** (Eintrag, Anker einer Gruppe, vernichtbarer Eintrag): statt `"se": "<x963>"` steht `"se": null` und
  `"hello": {"salt": "<32 B Base64>", "version": 1}` (Schlüsselreihenfolge `card`, `ct`, `fido`, `hello`, `nonce`, `se`).
  Das Salz ist je Versiegeln frisch.
- **V der Hello-Art** (Selbstvernichtung): `destruction.vKey = {"keyID": "<UUID>", "windowsHello": 1}` statt `publicKey`.
  Vernichtbare Siegel tragen dann `hello` statt `se`; die Art jedes Siegels muss zur Art seines Schlüssels passen
  (sonst `entry.sealedState` bzw. `payload.recoveryGroup`).
- **Herausforderung** (32 B, nicht geheim): `c = SHA-256("Siegel v2 windows hello entry challenge" ‖ vaultID(16) ‖
  keyID(16) ‖ id(16) ‖ salt(32))`; id = Eintrags-ID bzw. Gruppen-ID beim Anker; UUIDs in RFC-4122-Bytefolge.
- **Plattform** (App): `sig = RequestSignAsync(c)` (RSASSA-PKCS1-v1_5 mit SHA-256, deterministisch); an den Kern geht
  `roh = SHA-256("Siegel v2 windows hello entry" ‖ sig)` (32 B) über `IEntryFactorProvider.WindowsHelloSecretAsync`.
- **ss_se** = HKDF-SHA512(ikm = roh, salt = id, info = `"Siegel v2 entry windows hello"`, 32); für V:
  info = `"Siegel v2 entry destruction windows hello"`. Alles Weitere (K, AD, Notfall-Umschlag, Gruppen, Kit-Umschlag)
  unverändert wie §16.1/§23.1; die Info-Labels der Mac-Art (`"Siegel v2 entry se"`, `"… destruction"`) und der Hello-Art
  sind getrennt (Testvektor in `HelloTests.Testvektor_Herausforderung_und_ss`).
- **Versiegeln braucht die Signatur** (anders als die Mac-Art, die nur den öffentlichen Schlüssel braucht). Darum laufen
  Änderungen, die versiegeln, in Runden: zuerst sammelnd (`HelloSealing` merkt sich je (keyID, id) ein Salz und liefert
  einen Wegwerf-Wert), dann ohne Schreiben abgebrochen, Signaturen über den Anbieter geholt und mit denselben Salzen und
  Gruppen-IDs wiederholt (höchstens vier Runden). Auch Ersatz-Kennungen beim Import (Kennung schon vergeben) bleiben über
  die Runden gleich (`HelloSealing.ReplacementId(original, stelle)`, Befund krypto-3; vorher holte jede Runde eine
  Signatur für eine neue Zufalls-Kennung und scheiterte nach vier Runden). Versiegelnd und darum mit Runden: `UpsertAsync`,
  `SetProtectionAsync`, `ImportEntriesAsync`, `ConfigureDestructionAsync` (je Eintrag eine Signatur, je neue Gruppe eine
  für den Anker); die synchronen Varianten werfen in einem Hello-Tresor `FactorMissing(secureEnclave)` statt zu schreiben.
  `CommitRecoveryAsync`/`ChangeSecurityLevelAsync` geben die Gruppen über ihre Anker frei (eine Signatur je Gruppe). `UnlockedVault.EntryDeviceKeyKind` sagt der
  Oberfläche, welche Art eingerichtet ist.
- **Erkennen als „anderes Gerät“** im Swift-Kern seit **v4.6** (Integration, `../../../SPEC.md` §12): er liest
  `factors.windowsHello`, `hello` im Siegel und `windowsHello` im vKey, zählt beide Arten als Gerätefaktor, prüft die Art
  jedes Siegels wie C# (`deviceArtMatches`), deckt Siegel dieser Art nicht auf (`factorUnavailable(.secureEnclave)` ohne
  Anbieter-Aufruf), versiegelt nicht an sie und schreibt sie unverändert weiter. Kerne bis v4.5 melden
  `corruptFile("payload.recoveryGroup")` (gemessen).

### Entscheide und Abweichungen (Stufe B)

- `Clock.Canonical` am Rand des Bereichs (Jahr 9999): das nächste double rundet über das Ende hinaus; dann gilt das
  nächste darstellbare darunter, damit jeder geschriebene Zeitpunkt lesbar bleibt (gefunden mit
  `CheckDeadman(DateTimeOffset.MaxValue)`: vorher wurde V vernichtet und `zustand.json` war danach unlesbar). Swift
  rechnet mit `Date` bis 10^300 und kennt die Grenze nicht; ein Swift-Wert ausserhalb 1–9999 ist in C#
  `CorruptFile("payload.json")` bzw. `destruction.state` (Stufe A).
- Der Gerätefaktor heisst im Kern weiter `SecureEnclave` (Maskenbit 0); `FactorMissing/FactorUnavailable` nennen ihn
  `"secureEnclave"` – auch für Windows Hello.
- `PurgeBackups`/Markieren: ältere Sicherungen werden entfernt wie in Swift (auch am zweiten Ort; nicht erreichbar →
  Bericht `SecondaryUnreachable`, später `PurgeSecondaryBackups`).
- `DuressFile` vergleicht jetzt nach Wert (wie Swift `Equatable`).
- Fremde Ausnahmen werden an den Grenzen abgebildet: `CryptographicException` (P-256) → `Crypto("p256.…")`/
  `Crypto("entry.ecdh")`, Anbieter-Fehler → `FactorUnavailable(Art)`, Absage → `FactorCancelled`, KeePass-Werkzeug →
  `Io("export.kdbx")`. Gezielte CA1031-Unterdrückungen nur dort, mit Kommentar.
- Werkzeuge: genutzt werden `PasswordStrength.Estimate(pw).Level` (meta.strength), `MasterPasswordPolicy.Check(pw)`
  (Create, Passwortwechsel, Notfall, Vernichtungs-Passwort, Export-Passwort), `CsvExport.Export(items)` und
  `KeePassExport.Kdbx(items, pw)`. Seit der Integration sind es die echten Werkzeuge; die Testschalter `CsvExporter`/
  `KeePassExporter` bleiben, damit Tests sehen, was exportiert würde. Der echte Weg ist in `Tresor/WerkzeugeImKernTests.cs`
  geprüft (CSV-Export → CSV-Import → zweiter Tresor; KDBX → unabhängiger Leser; Bericht und Master-Regel mit zxcvbn).

## Interop-Beweis (18.10.2026)

1. **Mac → C#**: `v1_beispiel.siegel` und `v2_beispiel.siegel` öffnen mit echtem Argon2 (256 MiB) über Passwort (+ drei
   Faktoren) und über Notfallcode bzw. jedes Paar Teile in beiden Reihenfolgen; Inhalt = `referenz/erwartet_v*.json`;
   p-KAT, KEK-KAT (e), KEK_rec (c), Testvektor (a), Kit-Kennungen, Karten-Kennung. Der v1-Inhalt wird bytegleich neu
   kodiert; Fehlender Faktor/falsche Karte vor jedem Argon2.
2. **C# → Python**: `windows/tests/Fixtures/cs_v2_stufe_a.siegel` liest `referenz/siegel_referenz.py` (Prüfsumme, Kopf,
   KDF-Grenzen, Faktoren-HKDFs, pwSlot, Inhalt) – auch als Test (`CsFixtureTests.Python_Referenz_liest_die_CSharp_Datei`,
   läuft nur, wenn Python 3.12 und libsodium an den Mac-Standardorten liegen).
3. **C# → Swift → C#**: Eine vorübergehende Swift-Suite (unten; im Arbeitsordner wieder entfernt, das Original wurde
   nicht berührt) öffnete `cs_v2_stufe_a.siegel` mit dem Swift-Kern (`inspect`, `unlock` mit Faktoren, alle Werte),
   speicherte einen neuen Eintrag (Swift versiegelt ihn mit Schutz 2, legt Gruppe und `meta` an), öffnete wieder, prüfte
   die Teile (`checkRecoveryShares` = exakt) und stellte mit zwei Teilen wieder her. Ergebnis grün. Die dabei von Swift
   geschriebene Datei (`swift_v2_aus_cs.siegel`) und ein reiches Swift-JSON (`swift_inhalt_stufe_b.json`: Schutz 2–5,
   vernichtbar, Vernichtungs-Passwort, Totmann, Zähler, gelöscht, Sonderzeichen) liest C# wieder und **kodiert beide
   bytegleich neu** (`SwiftInteropTests`).
4. **C# (Stufe B) → Swift**: `windows/tests/Fixtures/cs_v2_beispiel.siegel` (Stufe 4, Schutz 1–5 versiegelt, Teile)
   öffnete eine zweite vorübergehende Swift-Suite (im Arbeitsordner wieder entfernt) mit dem Swift-Kern: `inspect`
   (Kit-Kennung), `unlock` mit `11…`/`22…`, alle Titel und Schutzstufen, **jeden Eintrag aufgedeckt** über einen
   Software-Anbieter (P-256-Skalar `88…`, q `22…`, Ausgabe `77…`) mit Passwort, Notiz, TOTP und Verlauf wie im README,
   gelöschten Eintrag wiederhergestellt und aufgedeckt, neuen Eintrag gespeichert und nach erneutem Öffnen aufgedeckt,
   `checkRecoveryShares` = exakt, `recover(shares:)` mit allen 7 Einträgen. Ergebnis grün.
5. **Windows-Hello-Art im Swift-Kern** (gleiche Suite, C#-Probedatei, nicht eingecheckt: Stufe 1, Hello-Schlüssel, ein
   Schutz-2-Eintrag): `unlock` → `corruptFile("payload.recoveryGroup")` – der heutige Swift-Kern übergeht
   `factors.windowsHello` und hält die Gruppe {SE} darum für ungültig. Siehe „Offen“.
6. **C# → Python** (Stufe B): `CsBeispielTests.Python_Referenz_liest_Kopf_und_Inhalt` (Kopf, Inhalt, 5 Siegel, 3 Gruppen).

7. **Seit der Integration fest im Repo** (W7): `../../../Tests/SiegelCoreTests/Interop/CSharpFixtureTests.swift` öffnet
   mit dem Swift-Kern `cs_v2_stufe_a.siegel` (Inhalt gegen `referenz/erwartet_v2_beispiel.json`, Weiterschreiben, Teile),
   `cs_v2_beispiel.siegel` (jeden Eintrag aufdecken, Papierkorb, jedes Paar Teile), `cs_v2_hello.siegel` und
   `cs_inhalt_hello.json` (Windows-Hello-Art: anderes Gerät, Notfallweg, bytegleich neu kodiert) und prüft die vom
   Swift-Kern weitergeschriebene `swift_hello_aus_cs.siegel`, die C# (`CsHelloTests`) wieder ganz über Windows Hello
   aufdeckt. Die Python-Referenz liest alle `cs_*.siegel` auch in `referenz/gegenprobe.sh`.

## Tests

`windows/tests/Siegel.Core.Tests/Kern/` (Stufe A und Fixtures):

| Datei | Inhalt |
|---|---|
| `KernHilfe.cs` | `KT`, `Fixtures` (findet die Repo-Wurzel), `Findings`, `TestTresor` (Datei jeder Stufe im Speicher, Testschalter-KDF), Sammlung `EchteProfile` |
| `TestvektorTests.cs` | (a), (c) KEK_rec, (d) Kopf-Auskunft + Kartenkennung + Teile, (e) Mehrfaktor-KAT, factorMissing/wrongCard ohne Argon2 |
| `BeispielDateiTests.cs` | (b)/(d) mit echtem Argon2 über beide Wege gegen `erwartet_v*.json`, KdfFailed ≠ WrongPassword, Neukodieren |
| `FormatV2Tests.cs` | Kopf-Rundlauf aller Masken/Schemata/Credential-Längen, Schreibprüfung, strenger Parser (16 Fälle), neuere Version, Herabstufung, Stufe ↔ Kopf, jede Stufe beide Wege, Längen |
| `ByteKippTests.cs` | jedes Byte × 3 Masken (Stufe 1, Stufe 5, Format v1, Mac-Dateien), Angreifer mit neuer Prüfsumme (Stufe 1, 5, v1), Kürzen/Verlängern, Migrations-KEK |
| `NotfallcodeTests.cs` | Eingabevarianten, Format, Füllbits, Prüfsumme, fremder Tresor, Korrektur (1, 2, Nachbarn, 4 „?“), Zufallscode, Schwärzung |
| `ShamirTests.cs` | GF(2^8), Testvektor (f), Zufall, Format, Korrektur pro Teil, Fehlerfälle |
| `CardCodeTests.cs` | Testvektor (f), Rundlauf, Fehler, Kennung, KEK-Bindung, Faktor-Länge, Eintrags-Hybridschlüssel = Mac-Inhalt |
| `KdfTests.cs` | Grenzen (lesen/schreiben/Testschalter), KdfFailed, Argon2-KAT (Python), Normalisierung, UI-Thread |
| `KryptoTests.cs` | SecureBuffer, AEAD, X25519-Kleinordnung, KEM-Rundläufe, Kombinierer (unabhängig nachgerechnet), Seed-Länge, Master-Tag |
| `InhaltTests.cs` | JSON-Schema/Sortierung/Nullwerte/Escapes, Swift-Zahlen, Zeit-Rundlauf, Swift-Leseregeln, Konsistenzregeln, Polster, Verlauf, Klon |
| `CsFixtureTests.cs` | C#-Fixture erzeugen (nur von Hand) und lesen, Python-Referenz |
| `SwiftInteropTests.cs` | Swift-JSON und Swift-weitergeschriebene Datei lesen und bytegleich neu kodieren |
| `CsBeispielTests.cs` | `cs_v2_beispiel.siegel` erzeugen (nur von Hand, `SIEGEL_CS_BEISPIEL_ZIEL`) und über den Store lesen: Werte, alle Einträge aufdecken, Teile, Neukodieren, Python |
| `CsHelloTests.cs` | Windows-Hello-Art: `cs_v2_hello.siegel` + `cs_inhalt_hello.json` erzeugen (nur von Hand, `SIEGEL_CS_HELLO_ZIEL`), lesen, über den Hello-Ersatz aufdecken, Notfallweg, bytegleich neu kodieren; `swift_hello_aus_cs.siegel` (vom Swift-Kern) lesen; Python |
| `KernHygieneTests.cs` | W3 bei jedem `dotnet test` (auch Release/Windows): kein Console/Debug/Trace, nur SiegelException nach aussen, keine unsichtbaren Zeichen, keine Normalisierung über ICU |
| `SwiftUnicodeTests.cs` | Eingefrorene Swift-Tresore mit U+FFFE (Eintrag, Master) und Unicode 16 (krypto-1/2/4): entsperren, reuseTag wie Swift, speichern, importieren, Wechsel, Notfallweg, Regel v4.7 |
| `KernReleaseHinweis.cs` | im Release-Bau: übersprungener Hinweis |

`windows/tests/Siegel.Core.Tests/Tresor/` (Stufe B; Gegenstücke der Kern*Tests.swift):

| Datei | Inhalt |
|---|---|
| `TresorHilfe.cs` | `KernVault`, `KernFaktoren`, `KernStufen`, `SchutzProvider` (Software-P-256 + Hello-Ersatz über HMAC), `SchutzTresor`, `VernichtungsProvider` (Software-V), `ZaehlEraser`, `VTresor` |
| `RundlaufTests.cs` | Anlegen/Entsperren, Fehler, Normalisierung, Sperren, Schwärzung, Polster, Feldgrenzen, Verlauf, Papierkorb, JSON, UI-Thread |
| `SpeichernTests.cs` | Generation, Rollback, `FileRollbackGuard`, fremde Änderung, Rücklese-Prüfung, Freiraum, Rechte, Temp-Reste, Sicherungen (Namen, Ausdünnen, zweiter Ort, Purge), Beschädigt-Pfad, Quarantäne, Export, Threads, KEK-Wiederverwendung |
| `ZugangTests.cs` | Passwort-/Profilwechsel, KDF-Grenzen, Policy, Wiederverwendung, Migration v1 → v2 je Schreibweg |
| `NotfallTests.cs` | Code und Teile: Rundlauf, Korrektur, Lebenszyklus, Kitwechsel, Sicherungswege, gewählte Datei, Kopf ungeprüft |
| `StufenTests.cs` | Stufen 1 ↔ 5, Faktoren einrichten/ersetzen, Regeln, Sicherungen der Stufe, Notfall setzt Stufe 1 |
| `SchutzTests.cs` | Schutz 1–5, Fehlerfälle, Sperren während der Freigabe, Notfall, Kit/Stufe mit Siegeln, Papierkorb, Import, Byte-Kippen, KAT (base, ss_se, K, reuseTag, Kombinierer), AD |
| `BerichtExportTests.cs` | Bericht §17, meta/reuseTag, CSV, KeePass, Import, Export-Orte (iCloud, OneDrive) |
| `VernichtungTests.cs` | §23: Einrichten, Totmann, Uhr rückwärts, Zähler, Sicherungswege, Löschschicht kaputt, Vernichtungs-Passwort (Sitzung, Zeitgleichheit, Ablage fehlt, Rotationen, ändern/entfernen), unlesbar, Zustand/Ablage-Format, Konsistenz |
| `BefundeTests.cs` | Datei-Befunde (Sperre während Argon2, purge scheitert, Notfall ohne Tresordatei), Befunde 16.10., Krypto-Befunde (F-Bindung, Rotation, reuseTag U+00A0), Fuzz-Befunde vernichtung-1…8 |
| `HelloTests.cs` | Windows-Hello-Art: Einrichten, Runden beim Versiegeln, Schutz 1–5, Fehler/Absage, Notfall/Kit, Import/Stufen, V der Hello-Art, Format/Mischformen, Testvektor |
| `KryptoBefundeWindowsTests.cs` | Befunde 18.10. (Windows): U+FFFE durch alle Wege ohne fremde Ausnahme, Hello-Import mit vergebenen Kennungen (je Eintrag eine Signatur), NFD/NFC bei Import, Verlauf, `ReplacingPassword`, `SetProtection` |
| `EchteProfileTests.cs` | Mac-Fixtures v1/v2 über den Store mit echtem Argon2, Standardprofil 1 GiB |
| `DateienTests.cs` | FileIO-Primitive (exklusiv, Links, Ersetzen, Klonen, Rechte, Auflisten) und `FileRollbackGuard` |
| `WerkzeugeImKernTests.cs` | Integration mit den echten Werkzeugen: CSV-Export → Import, KDBX → unabhängiger Leser, Bericht und Master-Regel mit zxcvbn |

## Offen

- Plattformschicht (Etappe 2): `FactorTemporarilyUnavailable`/`WrongSecurityKey` erzeugen, Windows-Hello-Anbieter
  (`WindowsHelloSecretAsync`), `CoreEnvironment.IsUiThread`, `IDestructionKeyEraser` mit `KeyCredentialManager.DeleteAsync`,
  BitLocker-Hinweis (`volumeIsEncrypted` fehlt im Kern bewusst), ggf. `SetProcessWorkingSetSize` (VirtualLock).
- Erster `dotnet test` unter Windows (die Windows-Zweige in `FileIO` sind nur auf dem Mac kompiliert); Gegenstück zum
  `chflags`-Test (vernichtung-5) mit Verweigern-ACL.
- **Bedienung der Hello-Art**: jede versiegelnde Änderung braucht eine Signatur je Eintrag (Import von n Einträgen in
  Stufe 4: n + Gruppen Windows-Hello-Abfragen, sofern Windows sie nicht zusammenfasst). Entscheid in SPEC-WINDOWS W12
  W1.1: so lassen und in Etappe 2 am Gerät messen; Sitzungs-Signatur vorerst verworfen.
- Der Gerätefaktor heisst im Kern weiter `SecureEnclave` (Maskenbit 0, Austauschbarkeit); die Oberfläche benennt ihn unter
  Windows „Windows Hello“ (`FactorKind.Title()` liefert noch den Mac-Text „Fingerabdruck“).
