# Siegel für Windows – Spezifikation W1 (bindend)

Siegel für Windows ist eine **eigene native App** (WinUI 3, .NET 10, keine Web-Technik), die **dasselbe Dateiformat**
und **dieselbe Kryptografie** wie die Mac-Version verwendet. Massgeblich für Format, Kryptografie, Regeln und Verhalten
ist `../SPEC.md` (Mac, v4.8). Diese Datei regelt nur, **wie** das unter Windows umgesetzt wird, und wo Windows bewusst
abweicht. Widerspricht etwas hier `../SPEC.md` beim Format oder bei der Kryptografie, gilt `../SPEC.md`.

## W0. Ziel und Etappen

- Ein Tresor ist zwischen Mac und Windows austauschbar, soweit es die Faktoren zulassen (W4.4).
- Etappe 1 (Mac, plattformneutral): `Siegel.Core` + `Siegel.Werkzeuge` + Tests + Interop-Beweis.
- Etappe 2 (Windows-PC): WinUI-3-App mit Stufen 1–2 (Passwort, Windows Hello), Schutz pro Eintrag 1–3, ganze
  Plattform-Härtung, MSIX ohne Netzwerk.
- Etappe 3 (Windows-PC): QR-Karte, FIDO2, Shamir-Kit-Druck, Stufen 3–5, Schutz 4–5, Selbstvernichtung, Exporte.

## W1. Aufbau

```
windows/
├── SPEC-WINDOWS.md                ← diese Datei
├── LIESMICH-WINDOWS.md            ← Stand, Bauen und Testen auf Mac und Windows, Interop-Beweise
├── Siegel.Windows.slnx
├── Directory.Build.props          ← gemeinsame Einstellungen (Nullable, Warnungen als Fehler, Analysatoren)
├── Directory.Packages.props       ← zentrale, exakt gepinnte Paketversionen
├── src/Siegel.Werkzeuge/          ← net10.0: Stärke (zxcvbn), Passphrase, Generator, TOTP, CSV, KeePass, Autofill-Abgleich
├── src/Siegel.Core/               ← net10.0: Format v1/v2, Krypto, Notfallcode, Shamir, Karte, Tresor, Stufen, Schutz
├── src/Siegel.Windows/            ← net10.0-windows10.0.26100.0, WinUI 3, MSIX (Etappe 2)
├── tests/Siegel.Core.Tests/       ← xUnit, läuft auf macOS UND Windows
├── tests/Fixtures/                ← von C# erzeugte Interop-Dateien (nie ändern, wie die Mac-Fixtures)
└── skripte/                       ← listen_exportieren.py, korpus_erzeugen.py, sperren_windows.sh/.py
```

- `Siegel.Core` und `Siegel.Werkzeuge` sind **plattformneutral** (kein `System.Windows`, kein WinRT) und laufen auf dem
  Mac in `dotnet test`. Alles Windows-Spezifische liegt in `Siegel.Windows` hinter Schnittstellen aus `Siegel.Core`
  (Faktor-Anbieter, Vernichtungsschicht, Uhr).
- Pakete exakt gepinnt, `RestorePackagesWithLockFile` + `packages.lock.json` (Hash-geprüfte Wiederherstellung), keine
  Wildcards. Zugelassen: `libsodium` 1.0.22 (nativ, P/Invoke, eigene dünne Bindung – keine Wrapper-Bibliothek),
  `BouncyCastle.Cryptography` 2.7.0, Test: `xunit` (+ Runner), Etappe 2/3: `Microsoft.WindowsAppSDK`,
  `ZXing.Net` (QR). Jedes weitere Paket nur mit Eintrag in W12.

## W2. Kryptobausteine (gemessen, 18.10.2026)

| Zweck | Baustein |
|---|---|
| Argon2id, XChaCha20-Poly1305, Zufall, `sodium_malloc`/`mprotect`, `sodium_pad`, X25519, BLAKE2b | libsodium 1.0.22 (NuGet `libsodium`, gleiche Version wie Mac) per P/Invoke |
| ML-KEM-1024 (aus 64-Byte-Seed), SHA3-256 | BouncyCastle 2.7.0 (`MLKemPrivateKeyParameters.FromSeed`, `Sha3Digest`) |
| HKDF-SHA512 | `System.Security.Cryptography.HKDF` (plattformneutral) |

- **Gemessen:** Für `R = 00…1f`, `vaultID = a0…af` ergibt C# exakt `SHA3-256(pkM) = 07d2a982…c206f2` und
  `pkX = 157638f5…213107` (SPEC §10 Testvektor a). Auf macOS sind `.NET`-`SHA3_256` und `MLKem` nicht verfügbar
  (`IsSupported = false`), darum überall BouncyCastle: gleicher Code auf beiden Plattformen.
- ML-KEM über BouncyCastle ist reiner verwalteter Code (nicht zeitkonstant garantiert wie CryptoKit) – ehrlich in
  `SICHERHEIT-WINDOWS.md`. Es wird nur für den Notfallweg und die Eintrags-Versiegelung gebraucht.
- `SecureBuffer` (SafeHandle über `sodium_malloc`, nach dem Befüllen `sodium_mprotect_readonly`, Freigabe nullt) für alle
  Schlüssel, Faktor-Werte, Passwort-Bytes, entschlüsseltes JSON. `string` lässt sich nicht nullen (ehrliche Grenze wie Mac).

## W3. Kern (`Siegel.Core`)

- Setzt `../SPEC.md` §1–§5, §13–§19, §23 **byte-genau** um: Format v1 lesen, v2 lesen/schreiben, KDF-Grenzen,
  Mehrfaktor-Ableitung, Slots, Inhalt (gleiches JSON), Notfallcode (Format, Korrektur, Kit-Kennung), Shamir,
  CardCode, Eintrags-Versiegelung, Stufen, Rotationen, Sicherungen (Namen, Ausdünnung, Anheften), Rollback,
  Bericht, Selbstvernichtungs-Zustand (`zustand.json`, Duress-Umschlag) – Plattformteile (Datei-Rechte, `F_FULLFSYNC`)
  werden durch Windows-Entsprechungen ersetzt (`FlushFileBuffers`, `MoveFileEx` mit `MOVEFILE_REPLACE_EXISTING |
  MOVEFILE_WRITE_THROUGH`, Pfade wie .NET mit `\\?\` ab 260 Zeichen, bei fremden Sperren bis 2 s wiederholt; neu
  angelegte Ordner mit geschützter ACL für den Benutzer, die eigene Paket-SID im AppContainer und SYSTEM, die ACL
  bestehender Ordner bleibt; W1.3).
- Öffentliche C#-Schnittstelle in Anlehnung an `../SPEC.md` §8/§22/§23.3 (gleiche Namen in PascalCase, `SiegelException`
  mit festem `SiegelErrorCode` + festem Detail-Code statt Swift-Enum). Schwere Aufrufe synchron, die App ruft sie über
  `Task.Run`.
- Fehler- und Protokollhygiene wie `../SPEC.md` §5: kein `Console.Write*`/`Debug.Write*`/`Trace`, keine Ausnahmen mit
  Inhalten, `ToString()` der Geheimnis-Typen geschwärzt. Eine Prüfung (`skripte/sperren_windows.sh`) bricht den Bau ab.

## W4. Faktoren unter Windows

### W4.1 Gerätefaktor (Maskenbit 0; Mac: Secure Enclave) = Windows Hello

- `Windows.Security.Credentials.KeyCredentialManager`: TPM-gebundener Schlüssel (RSA-2048) pro Tresor
  (`Siegel-<vaultID>-<keyID>`), Freigabe per Windows Hello (Biometrie oder Hello-PIN).
- Roher Faktorwert (32 B) = `SHA-256("Siegel v2 windows hello" ‖ RSA-PKCS#1-v1.5-SHA-256-Signatur über
  SHA-256("Siegel v2 windows hello challenge" ‖ vaultID ‖ keyID))`. PKCS#1 v1.5 ist deterministisch → stabiler Wert;
  beim Einrichten zweimal signieren und vergleichen, sonst Abbruch. Die HKDF aus `../SPEC.md` §13.1 rechnet der Kern.
- Ablage `Hardware/<keyID>.siegelhw` mit eigener Art (3 = Windows Hello), enthält nur den Schlüsselnamen.
- Eintrags-Schutz (`../SPEC.md` §16): Windows Hello kann kein ECIES. Daher: eigener Hello-Schlüssel für Einträge,
  `ss_se` = SHA-256-Ableitung aus der Signatur über eine **eintragsspezifische** Herausforderung (entryID, Zufalls-Salz
  im Umschlag). Schreiben ohne Finger geht dabei NICHT (Signatur nötig) → Bearbeiten eines geschützten Eintrags
  verlangt Windows Hello. Das Mac-ECIES-Format bleibt lesbar nur auf dem Mac; plattformspezifische Umschläge sind im
  Format als eigene Art gekennzeichnet (W12 dokumentiert die genaue Erweiterung, Swift-Kern muss sie als
  „anderes Gerät“ erkennen statt `corruptFile`).
- Ehrliche Grenzen: RSA-2048 ist nicht post-quanten; Windows Hello erlaubt die PIN statt Biometrie (keine
  „nur Finger“-Regel wie `.biometryCurrentSet`); ein neuer Finger macht den Schlüssel nicht ungültig.
- Vernichtung (§23): `KeyCredentialManager.DeleteAsync` für den Vernichtungsschlüssel.

### W4.2 QR-Karte

- Format identisch (`CardCode`). Kamera über `Windows.Media.Capture.MediaCapture` + `MediaFrameReader`, Dekodierung
  mit ZXing.Net (nur QR), Bilder nur im Speicher, Kamera sofort stoppen. Druck über Win32-Druck (Etappe 3).

### W4.3 Sicherheitsschlüssel (FIDO2)

- Über die Windows-eigene API `webauthn.dll` (rohes HID ist unter Windows für normale Prozesse gesperrt):
  `WebAuthNAuthenticatorMakeCredential` mit `hmac-secret`, `WebAuthNAuthenticatorGetAssertion` mit zwei Salzen.
- **Offen (Etappe 3 klärt am SDK):** ob die API rohe hmac-secret-Salze erlaubt oder nur PRF (gehashte Salze). Nur bei
  rohen Salzen ist ein Mac-Schlüssel unter Windows nutzbar; sonst ist der FIDO2-Faktor plattformspezifisch (dokumentiert).
- Mit echter Hardware ungetestet, bis ein Schlüssel vorhanden ist.

### W4.4 Austauschbarkeit

- Stufe 1 und alle Faktoren ausser dem Gerätefaktor sind zwischen Mac und Windows austauschbar.
- Ab Stufe 2 öffnet ein Mac-Tresor unter Windows (und umgekehrt) nur über den Notfallcode; danach Stufe 1 (wie §16.1).
- Ein unter Windows geschriebener Tresor bleibt für den Mac lesbar (Interop-Test in beide Richtungen).

## W5. Plattform-Härtung (Etappe 2)

- **MSIX ohne Netzwerk:** AppContainer ohne `internetClient`, `internetClientServer`, `privateNetworkClientServer`.
  Einzige Fähigkeit: `webcam` (Karte). Lokale Signatur mit eigenem Zertifikat.
- **Fensterschutz:** `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` für JEDES Fenster des Prozesses
  (Hauptfenster, Popups/Flyouts, Dialoge, Dateiauswahl soweit möglich), beim Erzeugen und regelmässig per
  `EnumThreadWindows` nachgezogen. Geheimnis-Ansichten prüfen den Zustand und verdecken sonst.
- **Zwischenablage:** `Clipboard.SetContentWithOptions` mit `IsAllowedInHistory = false`, `IsRoamable = false`, dazu die
  Formate `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory` = 0,
  `CanUploadToCloudClipboard` = 0; Leeren nach Ablauf nur, wenn `GetClipboardSequenceNumber` noch unserer ist.
- **Prozess-Härtung** (`SetProcessMitigationPolicy`): `ExtensionPointDisable` (keine AppInit-/Hook-DLLs),
  `ImageLoad` (keine Remote-/Low-Label-Images), `StrictHandleCheck`, `ChildProcessPolicy` (keine Kindprozesse).
  Wenn **NativeAOT** für die WinUI-App gelingt, zusätzlich `DynamicCode` (kein JIT, kein ausführbarer neuer Speicher).
  WER: keine Abbilder (`WerAddExcludedApplication` für die eigene App, `SetErrorMode`).
- **Auto-Sperre:** Inaktivität in der App, `WTSRegisterSessionNotification` (Sperren, Abmelden, Benutzerwechsel),
  Energie-Ereignisse (Standby), Fenster minimiert (Stufe ≥ 3).
- **Einzelinstanz:** `AppInstance.FindOrRegisterForKey("Siegel")`.
- **Eingabefelder:** Rechtschreibung, Textvorhersage, Diktat und IME-Vorschläge in Geheimnisfeldern aus
  (`IsSpellCheckEnabled = false`, `IsTextPredictionEnabled = false`, `InputScope` passend); Master-Passwort nur in
  `PasswordBox`. Bildschirmlupe/Bedienungshilfen: Geheimnisse nicht als UIA-Wert (`AutomationProperties`).
- **Kein Persistieren von Inhalten** (keine Sprunglisten, kein Zeitachsen-/Aktivitätsverlauf, keine Suche im Startmenü).

## W6. Oberfläche

Gleiche Gestaltung wie `../SPEC.md` §7: rein weiss, schwarze Schrift, Nebentext #6E6E6E, Haarlinien #E5E5E5, keine
Akzentfarbe (Systemakzent überschreiben), kein Mica/Acrylic, eigene Titelleiste. Schrift Segoe UI Variable,
Passwörter/Codes Cascadia Mono. Logo „Schlüssel-S“ als XAML-`Path` aus der Geometrie in `../design/LOGO.md`. Texte Deutsch
(Schweiz, ss), gleiche Formulierungen wie die Mac-Version, wo möglich wörtlich. Snapshots mit `RenderTargetBitmap`
(Etappe 2).

## W7. Tests und Beweise

- `dotnet test` auf dem Mac und auf Windows: Format/Krypto/Stufen/Shamir/Karte/Versiegelung/Zustand/Werkzeuge.
- **Interop in beide Richtungen:** C# öffnet `../Tests/SiegelCoreTests/Fixtures/v1_beispiel.siegel` und
  `v2_beispiel.siegel` (Passwort, Faktoren, Notfallcode) mit genau dem erwarteten Inhalt
  (`../referenz/erwartet_v*.json`); C# erzeugt `tests/Fixtures/cs_v2_beispiel.siegel` (Stufe 4 mit festen
  Faktor-Werten, Shamir-Teilen, versiegelten Einträgen Schutz 1–5), die **der Swift-Kern** (neuer Test
  `../Tests/SiegelCoreTests/Interop/`) und **die Python-Referenz** öffnen.
- **Stärke bit-genau gleich:** Ein Swift-Hilfsprogramm gibt die Schätzung für einen festen Korpus (≥ 10 000 Passwörter,
  generiert + typische Muster) aus; C# muss für jedes Passwort dieselben Bits (Abweichung ≤ 1e-9) und dieselbe Stufe liefern.
  Die Wortlisten haben **eine** Quelle: ein Skript erzeugt aus den Swift-Listen die C#-Ressourcen.
- Byte-Kipp über jedes Byte (wie Mac), Generator-Gleichverteilung, CSV-/TOTP-/KDBX-Vektoren wie Mac.
- **Normalisierung bit-genau gleich** (W1.2): ein Korpus mit Swifts `precomposedStringWithCanonicalMapping` und
  `PasswordNormalizer.normalize` (jedes Zeichen der NFC-Tabelle, alle Paare, alle Unicode-16-Zerlegungen, Hangul,
  U+FFFE, Zufall) und einer mit Swifts `String ==`; beide laufen ohne Xcode, also auch unter Windows.

## W8–W11 (Etappe 2/3, werden dann präzisiert)

Datenort (`ApplicationData.LocalFolder\Siegel`), zweiter Sicherungsort (FolderPicker + FutureAccessList), Druck,
Autofill (Windows hat keine dem macOS-Credential-Provider gleichwertige systemweite Schnittstelle für Drittanbieter
ausser Browser-Erweiterungen → bewusst weggelassen), Updates (keine; lokal gebaut).

## W12. Änderungsprotokoll

- W1 (18.10.2026): Erstfassung. Gemessen auf dem Mac: libsodium 1.0.22 (NuGet) und BouncyCastle 2.7.0 treffen den
  ML-KEM-1024- und X25519-Testvektor exakt.
- W1.1 (18.10.2026): Etappe 1 integriert (Kern Stufe A + B, Werkzeuge; Stand und Befehle in `LIESMICH-WINDOWS.md`).
  `dotnet test` 548 Tests grün (Debug; Release 244 + 1 Hinweis), `swift test` 507 grün. Keine neuen Pakete; das
  Swift-Paket hat ein zusätzliches Debug-Hilfsprogramm `SiegelStaerkeExport` (Stärke-Referenz für W7). Bewusste
  Abweichungen und Präzisierungen:
  - **Windows-Hello-Art (W4.1), Version 1** – die in W4.1 angekündigte Formaterweiterung. Inhalt: `factors.windowsHello
    = {"keyID", "version": 1}` (dann `factors.secureEnclave = null`, nie beide); im Siegel `"hello": {"salt": 32 B,
    "version": 1}` statt `"se"`; V der Hello-Art `destruction.vKey = {"keyID", "windowsHello": 1}`. Herausforderung
    c = SHA-256(`"Siegel v2 windows hello entry challenge"` ‖ vaultID ‖ keyID ‖ id ‖ salt) mit id = Eintrag bzw.
    Gruppe (Anker); die Plattform liefert roh = SHA-256(`"Siegel v2 windows hello entry"` ‖ RSASSA-PKCS1-v1_5-SHA-256-
    Signatur über c) mit dem Schlüssel `Siegel-<vaultID>-<keyID>`; ss = HKDF-SHA512(roh, salt = id, info = `"Siegel v2
    entry windows hello"` bzw. für V `"Siegel v2 entry destruction windows hello"`, 32). Alles Weitere (K, AD,
    Notfall-Umschlag, Gruppen, Kit) wie `../SPEC.md` §16.1/§23.1. Testvektor in `HelloTests`, mit Python nachgerechnet.
    Der Swift-Kern erkennt die Art ab v4.6 als „anderes Gerät“ (`../SPEC.md` §12 v4.6).
  - **Versiegeln braucht Windows Hello**: Änderungen, die versiegeln, laufen in Sammel-/Liefer-Runden über
    `UpsertAsync`, `SetProtectionAsync`, `ImportEntriesAsync`, `ConfigureDestructionAsync`, `CommitRecoveryAsync`,
    `ChangeSecurityLevelAsync` (je Eintrag eine Signatur, je neue Gruppe eine für den Anker); die synchronen Varianten
    werfen in einem Hello-Tresor `FactorMissing(secureEnclave)` und schreiben nichts. W3 („schwere Aufrufe synchron“)
    gilt damit nur für Tresore ohne Hello-Art. Bedienung bei grossen Importen in Stufe 4/5 (n Abfragen) misst
    Etappe 2 am Gerät; die Alternative „eine Sitzungs-Signatur, je Eintrag nur HKDF“ ist vorerst verworfen (keine
    Trennung je Eintrag).
  - **Schnittstelle** (W3, PascalCase): `RecoveryScheme.single` heisst `SingleCode` (Analyse-Regel CA1720), dazu
    `KdfParameters`, `IEntryFactorProvider` (async mit `CancellationToken`, `WindowsHelloSecretAsync`), `FactorSet` als
    `[Flags] enum`, `UnlockOutcome` als Klasse, `GetDestructionStatus()`, `VaultStore.ReadBackupInfo(path)`, `VaultPath`,
    `HardwareKeyPath`, `BackupsDirectory`, `UnlockedVault.EntryDeviceKeyKind`. `LevelPolicy` folgt dem Swift-Code
    (`DefaultEntryProtection`; `perEntryRelease` aus SPEC §22 gibt es auch in Swift nicht). Der Gerätefaktor heisst im
    Kern weiter `SecureEnclave` (Maskenbit 0, Fehlerdetail `secureEnclave`), auch für Windows Hello.
  - **Fehler**: `SiegelErrorCode` (`Modell.cs`) um `FactorTemporarilyUnavailable` (Detail `se.lockout`,
    `se.notReachable`, `fido.busy`) und `WrongSecurityKey` ergänzt (angehängt, bisherige Werte gleich). Wo Swift mit
    `precondition` beendet, wirft C# `SiegelException(Crypto, fester Code)` (`mlkem.seedLength`, `secure.readonly`,
    `header.fields` …). Nach aussen nur SiegelException; die drei internen Ausnahmen (`FileIO.ExistsException`,
    `HelloMaterialNeededException`, `CryptographicException` in `P256`) sind je Datei freigegeben und werden im Kern
    abgefangen (`skripte/sperren_windows.py`, `KernHygieneTests`).
  - **JSON**: geschrieben wie gemessen von Swift (ordinal sortiert, `\/`, `\u00xx` klein, Swift-Zahlen, Nullwerte; jetzt
    auch in `../SPEC.md` §12 v4.6). Gelesen wie Swift: bei doppelten Schlüsseln gilt der erste, Ganzzahl auch aus `1.0`,
    nur striktes Base64, UUID nur 36 Zeichen.
  - **Zeitbereich**: `DateTimeOffset` reicht nur von Jahr 1 bis 9999 (Swift `Date` weiter). Beim Schreiben rundet
    `Clock.Canonical` am Rand nach innen; fremde Werte ausserhalb sind `CorruptFile`. Praktisch ohne Bedeutung.
  - **Kryptografie**: ML-KEM über BouncyCastle (nicht garantiert zeitkonstant, Objekte nicht nullbar); Zufall fürs
    ML-KEM-Kapseln aus dem Betriebssystem über .NET, alles andere aus libsodium. `sodium_malloc` sperrt unter Windows
    nur bis zur Arbeitssatz-Grenze (`VirtualLock`); die App erhöht sie bei Bedarf (`SetProcessWorkingSetSize`).
    Gehört nach `SICHERHEIT-WINDOWS.md` (Etappe 2).
  - **Speichern** (W3): Sicherung = lesen + exklusiv schreiben (kein APFS-Klon), Ordner-fsync nur unter Unix,
    `FileRollbackGuard` (Textdatei) statt UserDefaults, Export-Orte unter OneDrive (Umgebungsvariablen) und iCloud
    abgelehnt. Datenort, BitLocker-Hinweis (`volumeIsEncrypted`) und Löschschicht (`KeyCredentialManager.DeleteAsync`)
    setzt die App (Etappe 2). Die Windows-Zweige (`MoveFileExW`, ACL, `NotContentIndexed`) sind bisher nur auf dem Mac
    kompiliert; `dotnet test` unter Windows steht aus.
  - **Werkzeuge**: Graphem-Zerlegung (UAX #29 mit GB9c), Gross-/Kleinschreibung und Buchstaben/Zahlen nach einer aus
    Swift exportierten Unicode-Tabelle statt .NET/ICU (sonst andere Bits als Swift); eigenes `lgamma`; NFC ohne
    Ausnahme bei U+FFFE. Für die Master-Regel nimmt C# `"siegel"` und `Environment.UserName` samt Teilen; der volle
    Name bleibt leer (kein Gegenstück zu `NSFullUserName()` ohne Plattform-API). `TotpParameters` hält das Geheimnis in `sodium_malloc` (IDisposable).
    HMAC-SHA1 (CA5350) gezielt erlaubt, weil RFC 6238 es verlangt. KDBX-UUIDs in RFC-Bytefolge.
  - **Tests**: Die Kern-Tests brauchen die DEBUG-Testschalter (wie Swift `@testable`); im Release-Bau zeigt ein
    übersprungener Hinweistest das an. Interop-Fixtures in `tests/Fixtures/` (`cs_*` von C#, `swift_*` vom Swift-Kern),
    eingefroren, Werte in deren `README.md`.
- W1.2 (18.10.2026): Krypto-Befunde der Prüfung (krypto-1 bis krypto-4); `dotnet test` 566 grün (Release 251 + 1 Hinweis), `swift test` 511 grün.
  - **Normalisierung nie über .NET/ICU** (krypto-1, krypto-2): `string.Normalize` warf bei U+FFFE eine ArgumentException
    (ein Mac-Tresor mit U+FFFE in einem Passwort war unter Windows weder per Passwort noch per Notfallcode zu öffnen) und
    hing an der ICU des Systems (Unicode 16: andere Argon2-Bytes als Swift; ein Windows-Update hätte einen Windows-Tresor
    aussperren können). Jetzt rechnet `Siegel.Werkzeuge/Unicode/SwiftNormalisierung.cs` aus der Tabelle
    `swift_nfc.txt.gz`, die `SiegelStaerkeExport nfc` auf dem Mac **misst**: Foundation-NFC (`D`/`O`/`C`/`K`/`P`, mit
    Foundations gemessenen Eigenheiten, `../SPEC.md` §12 v4.7) für Master-Passwort, reuseTag und Master-Tag; die NFC der
    Swift-Standardbibliothek (`SD`/`SC`/`SP`/`SX`) für die Gleichheit von Swift-`String`; das Unicode-Alter (`A`) für die
    Regel. Die Grep-Sperre (`sperren_windows.py`, `KernHygieneTests`) verbietet `NormalizationForm`, `IsNormalized` und
    `.Normalize()` in Kern und Werkzeugen. Master-Passwort-Regel wie Mac v4.7: nur Zeichen aus Unicode 15.0.
  - **Vergleiche wie Swift-`String`** (krypto-4): Doppel-Erkennung beim Import (Host + Benutzer, Passwort), Verlaufsregel
    in `Upsert`/`SetProtection`/`ReplacingPassword` über `SwiftStringComparer` (kanonisch gleich, ohne Leerzeichen-
    Abbildung) statt ordinal.
  - **Windows-Hello-Art, Import** (krypto-3): Ersatz-Kennungen für schon vergebene Kennungen hält `HelloSealing`
    über alle Sammelrunden gleich (`ReplacementId(original, stelle)`), sonst gehörte jede Signatur der Vorrunde zu einer
    verworfenen Kennung (vorher 4 Runden × n Abfragen, dann `FactorMissing`).
  - Beweise: `Werkzeuge/NormalisierungTests` (Korpora `nfc_*`, `gleich_*`), `Kern/SwiftUnicodeTests` (eingefrorene
    Swift-Tresore `swift_fffe_eintrag/master.siegel`, `swift_kirat_master.siegel`), `Tresor/KryptoBefundeWindowsTests`.
- W1.3 (18.10.2026): Robustheits-Befunde der Prüfung (robust-1 bis robust-8); `dotnet test` 589 grün (Release 251 + 1
  Hinweis), `swift test` 517 grün. Beide Kerne zusätzlich in `../SPEC.md` §12 v4.8 (robust-7 Kopfzeile, robust-8). Beweise: `Tresor/RobustBefundeWindowsTests.cs` (die Tests `Windows_…` prüfen die
  Windows-Zweige erst beim ersten `dotnet test` unter Windows), Swift `Kern/KernRobustBefundeTests.swift`.
  - **Speichern, fremde Sperren** (robust-1): Defender, Windows-Suche, Sicherungs-Agenten und die Explorer-Vorschau öffnen
    frische Dateien kurz ohne `FILE_SHARE_DELETE`; `MoveFileExW` scheitert dann mit 5/32 (rename(2) kennt das nicht).
    `Rename`/`RenameExclusive` wiederholen bei 5 und 32 bis 2 s (Pause 10, 20, 40 … ms, höchstens 500; wie Go
    `cmd/go/internal/robustio`), `RenameExclusive` prüft vor jedem Versuch das Ziel (80/183 → vorhanden). Temp-Dateien und
    halbe Kopien gescheiterter Schreibvorgänge entfernt `RemoveTemp` ebenso. Kein Format- oder Verhaltensunterschied zu
    Swift. Offen (auch in Swift): Temp-Reste im Hardware-Ordner räumt niemand auf.
  - **Ordner-ACL** (robust-4; präzisiert W3 „ACL nur für den Benutzer“, das W5 widersprach): Ein AppContainer-Token
    braucht für jeden Zugriff zusätzlich einen Eintrag für die Paket-SID; die bisherige ACL nur für den Benutzer sperrte
    die App nach dem ersten Speichern aus ihren eigenen Ordnern aus, und `SetAccessControl` verteilte sie bei jedem
    Speichern auf alle Dateien. Jetzt: nur **neu angelegte** Ordner bekommen eine geschützte ACL (Benutzer, eigene
    Paket-SID aus `TokenAppContainerSid`, SYSTEM für Zurücksetzen/Deinstallation); lässt sich der Token nicht befragen,
    bleibt die geerbte ACL. Bestehende Ordner (`LocalState`, Tresorordner) behalten ihre ACL; unter Unix setzt der Kern
    weiter 0700 wie Swift `chmod`. `FileRollbackGuard` legt seinen Ordner nur an, wenn er fehlt (eigener Unterordner, nie
    direkt `LocalState`). Etappe 2: Test unter AppContainer (anlegen, speichern, neu öffnen, `icacls`).
  - **Lange Pfade** (robust-6): eigene `MoveFileExW`-Aufrufe bekommen ihre Pfade wie .NET für FileStream (`GetFullPath`,
    dann `\\?\` bzw. `\\?\UNC\` ab 260 Zeichen oder mit Punkt/Leerzeichen am Ende), sonst galt dort MAX_PATH
    (`longPathAware` + `LongPathsEnabled` sind standardmässig aus): ein zweiter Sicherungsort tief auf einem NAS war immer
    `Failed`, ein Export fiel still auf das nicht atomare Schreiben zurück. `MOVEFILE_WRITE_THROUGH` bleibt (kein
    `File.Move`).
  - **Beschädigte, übergrosse Tresordatei** (robust-5): Die Sicherung „beschaedigt-…“ einer unlesbaren Datei wird gestreamt
    und ohne Grössengrenze kopiert (`FileIO.CopyExclusiveStreamed`; Swift: `clonefile`), sonst scheiterte „Neueste lesbare
    Sicherung öffnen“ (und der Notfallweg) bei einer über 64 MiB gewachsenen Datei an `io("backup.clone")`. Danach müssen
    64 MiB frei bleiben, sonst `notEnoughDiskSpace` vor dem Schreiben.
  - **Totmann-Frist** (robust-3): `DateTimeOffset` reicht nur bis 9999; Frist = letzte echte Entsperrung + Tage wird am Rand
    gesättigt (`Clock.AddDaysSaturating`) statt `ArgumentOutOfRangeException` (fremde `zustand.json` mit Dezember 9999).
    `CheckDeadman` bleibt bei „unbrauchbare Uhr: nichts“ (wie Swift, wo die Frist dann nie erreicht wird).
  - **Host-Schlüssel beim Import** (robust-2): `HostKey` über das Foundation-Modell `UrlHost` (wie der Autofill-Abgleich)
    statt `Uri.IdnHost`, das bei Hosts wie `bank.`U+FFFD`.ch` eine `UriFormatException` warf (ein gespeicherter Eintrag
    blockierte jeden Import). Dazu wie Swift: Trimmen und Kleinschreibung nach Swift-Tabellen, und `contains("://")` nur an
    Character-Grenzen (`SwiftText.EnthaeltFolge`, auch im Autofill-Abgleich und im CSV-Titel).
  - **CSV ohne quadratische Laufzeit** (robust-7): IDNA (ICU) nur für Hosts bis 2048 Byte UTF-8, wie Foundation gemessen
    (darüber kein Host, also Titel = URL und `csv.field.title` wie Swift); Kopfzeile wie `../SPEC.md` v4.8.
  - **Doppelte Eintrags-Kennungen** (robust-8): wie `../SPEC.md` v4.8, in `PayloadCodec.ReadContent`.
