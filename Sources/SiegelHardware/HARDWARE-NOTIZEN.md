# SiegelHardware – Notizen für die Oberfläche

Modul nach SPEC §14, §16 (SE-Teil), §21 (Signatur) und §22. Alle Faktor-Werte verlassen das Modul **roh**
(ECDH_SE, hmac-secret-Ausgabe, je 32 B in `FactorSecret`); die HKDFs aus §13.1/§16.1 rechnet nur der Kern.

| Datei | Inhalt |
|---|---|
| `SecureEnclave/SecureEnclaveFactor.swift` | öffentliche API, Ablauflogik (`SecureEnclaveEngine`) |
| `SecureEnclave/SecureEnclaveBackend.swift` | CryptoKit-Secure-Enclave + LocalAuthentication, Fehlerabbildung |
| `SecureEnclave/HardwareKeyFile.swift` | Schlüsseldatei `<keyID>.siegelhw` (Format im Dokukommentar), v4.3: Backup-Ausschluss, `destroy` |
| `Karte/CardImage.swift` | QR-Bild (CIQRCodeGenerator, Stufe M, ganzzahlig skaliert, Ruhezone 4) |
| `Karte/QRDetector.swift`, `Karte/QRScanner.swift` | Vision-Erkennung, Kamera-Scanner |
| `FIDO2/*` | CBOR, CTAPHID, PIN/UV-Protokolle 1+2, CTAP2, IOHID-Transport, `SecurityKeyFactor` |
| `Signatur/CodeSignatureCheck.swift` | Selbstprüfung der Signatur |

## Threading (wichtig)

- **Secure Enclave blockiert** bis Touch ID beantwortet ist: `enroll`, `enrollEntryKey`, `secret`, `sharedSecret` nie
  auf dem Main-Thread aufrufen. Sie prüfen `dispatchPrecondition(.notOnQueue(.main))` (Absturz im Fehlerfall, wie
  bei Argon2). Aufruf: `try await Task.detached(priority: .userInitiated) { try SecureEnclaveFactor.secret(…) }.value`.
  `isAvailable`, `remove` und `destroy` zeigen keinen Dialog und dürfen überall laufen.
- **SecurityKeyFactor blockiert** bis zur Berührung (Frist **30 s je Berührung**): `register` braucht zwei Berührungen
  (Registrieren, dann eine Assertion mit beiden Salzen), `secret` eine. Ebenfalls `dispatchPrecondition`, also
  `Task.detached`. Vorher in der Oberfläche „Berühre jetzt deinen Sicherheitsschlüssel“ zeigen.
- **QRScanner ist `@MainActor`**: `init`, `start`, `stop`, `previewLayer` auf dem Main-Thread. `onPayload` läuft auf
  dem Main-Thread, genau einmal pro `start()`; danach ist die Sitzung schon gestoppt (Kamera aus). Kamera-Start und
  -Stopp laufen intern auf einer eigenen Queue.
- `CardImage.qr` und `CodeSignatureCheck.mainBundleIsValid()` sind schnell (Millisekunden), aber rechnen. Die
  Signatur prüft `AppModel.production` bewusst **synchron** als Erstes (v4.4): kein Zeitfenster, in dem vor dem
  Ergebnis entsperrt werden könnte.
- **Abbrechen beim Sicherheitsschlüssel** (v4.4): pro Versuch ein `SecurityKeyCancellation` mitgeben und bei
  „Abbrechen“/Sperren `cancel()` rufen. Der Kanal prüft es mindestens alle 100 ms (auch im Warten bei
  ERR_CHANNEL_BUSY), beendet eine offene Anfrage mit CTAPHID_CANCEL und schliesst die Verbindung → `factorCancelled`.

## Fehler → Oberfläche

| Fehler | Bedeutung | Vorschlag |
|---|---|---|
| `factorCancelled` | Touch ID abgebrochen / Finger nicht erkannt; Schlüssel nicht berührt (30 s) oder abgelehnt | still zurück, erneut versuchen |
| `factorUnavailable(.secureEnclave)` | Schlüsseldatei fehlt/beschädigt, Biometrie geändert (`.biometryCurrentSet`), keine Finger mehr eingerichtet; nur wenn Touch ID gerade bereit ist (sonst vorübergehend, v4.4) | Notfallweg anbieten, „Erneut versuchen“ bleibt ein sichtbarer Knopf (bau-1) |
| `factorTemporarilyUnavailable(.secureEnclave, "se.lockout")` | Touch ID nach zu vielen Fehlversuchen gesperrt (LAError -8, in der Fehlerkette oder per `canEvaluatePolicy` ohne Dialog) | „Mac einmal mit Passwort entsperren, erneut versuchen“, **kein** Notfallweg |
| `factorTemporarilyUnavailable(.secureEnclave, "se.notReachable")` | Sensor nicht erreichbar: Deckel zu, Tastatur mit Touch ID nicht verbunden/gekoppelt (-6, -13, -12) | „Deckel öffnen bzw. Tastatur anschliessen, erneut versuchen“, kein Notfallweg |
| `factorUnavailable(.card)` | keine Kamera-Freigabe, keine eingebaute Kamera (Deckel zu) | Code abtippen anbieten (`CardCode.decode`) |
| `factorUnavailable(.securityKey)` | kein Schlüssel, Gerät abgezogen, kein hmac-secret, Gerät verlangt PIN/UV, kaputte Antwort | „… abgezogen, antwortet nicht oder verlangt eine PIN-Prüfung …“ + Notfallweg |
| `wrongSecurityKey` | anderer oder zurückgesetzter Schlüssel: CTAP2_ERR_NO_CREDENTIALS (0x2E), v4.4 | „Nicht der Sicherheitsschlüssel dieses Tresors …“ + Notfallweg |
| `factorTemporarilyUnavailable(.securityKey, "fido.busy")` | ERR_CHANNEL_BUSY über die ganze Frist (anderes Programm hält den Schlüssel), v4.4 | „gerade beschäftigt, kurz warten“ |
| `crypto("se.verify")` | Prüfung beim Einrichten ergab ein anderes ECDH – nichts geschrieben | „Einrichten fehlgeschlagen, erneut versuchen“ |
| `crypto("se.publickey")` | ungültiger ephemerer Schlüssel aus dem Inhalt (vom Kern) | wie beschädigter Eintrag |
| `crypto("fido.input")` | credentialID nicht 16…1024 B oder Salz ≠ 32 B (Kopf kaputt) | wie beschädigte Datei |
| `io("hw.write")`, `io("hw.directory")`, `io("hw.remove")` | Schlüsseldatei nicht schreibbar/entfernbar (auch: Backup-Ausschluss liess sich nicht setzen) | Speicherfehler-Meldung |
| `io("hw.destroy")` | Vernichten: Datei überschrieben, aber nicht löschbar (Ordner ohne Schreibrecht) | Speicherfehler-Meldung |

## Abläufe

**Einrichten (Stufenwechsel, §13/§16):**
```swift
let dir = store.hardwareDirectory                       // <Tresorordner>/Hardware, wird bei Bedarf 0700 angelegt
let se = try SecureEnclaveFactor.enroll(directory: dir)              // 1× Touch ID („Touch ID für Siegel einrichten“)
let entry = try SecureEnclaveFactor.enrollEntryKey(directory: dir)   // 1× Touch ID („… für geschützte Einträge …“)
let key = try SecurityKeyFactor.register(on: device)                  // 2× berühren (nur Stufe 5 / Schutz 5)
let material = NewFactorMaterial(secureEnclave: se, entryKey: entry, card: CardEnrollment(q: q), securityKey: key)
```
Abwärts: erst nach erfolgreichem Schreiben `SecureEnclaveFactor.remove(keyID:directory:)` für nicht mehr gebrauchte
Schlüssel. Scheitert das Schreiben nach `enroll`, die neue Datei ebenfalls mit `remove` wegräumen.

**Karte:** `q = CardCode.generate()`, Bild `CardImage.qr(payload: CardCode.payload(for: q), pixels: 1200)` (im Druck
gross genug: ≥ 4 cm), darunter `CardCode.groupedText(for: q)`. Nach dem Drucken einmal scannen: `QRScanner` →
`CardCode.decode(payload)` → mit `q` vergleichen → erst dann schreiben. Das `CGImage` enthält das Kartengeheimnis:
nur anzeigen/drucken, nie speichern oder cachen. Die Vorschau (`previewLayer`) zeigt Kamerabilder: nur in einem
Fenster unter dem WindowGuard. `QRScanner` liefert nur Inhalte mit Präfix `SIEGELKARTE` (andere QR-Codes im Bild
werden übergangen) und höchstens 256 Zeichen; die Prüfsumme prüft `CardCode.decode`. Beim Sperren `stop()`.
Kamera-Freigabe: Ist `QRScanner.authorization()` `.notDetermined`, zuerst `await QRScanner.requestAccess()`; bei
`.denied`/`.restricted` wirft `start()` `factorUnavailable(.card)` → Abtippen anbieten (und auf Systemeinstellungen →
Datenschutz → Kamera hinweisen).

**Entsperren:** `let info = try store.inspect()`, dann für `info.factors`:
- `.secureEnclave`: `SecureEnclaveFactor.secret(keyID: info.seKeyID, directory: store.hardwareDirectory, reason: "Siegel entsperren")`
- `.card`: scannen (oder abtippen) → `CardCode.decode`; falsche Karte erkennt `CardCode.tag(for:vaultID:)` gegen `info.cardTag`
- `.securityKey`: `SecurityKeyFactor.secret(on: device, credentialID: info.fidoCredentialID, salt: info.fidoSalt,
  cancellation: token)`

Dann `store.unlock(masterPassword:factors:)`. Jeder SE-Aufruf nutzt einen frischen `LAContext` (keine Wiederverwendung).

**Eintrag aufdecken (§16):** Die Oberfläche implementiert `EntryFactorProvider` etwa so:
```swift
struct UIEntryFactors: EntryFactorProvider {
    let directory: URL; let device: SecurityKeyDevice?; let scanCard: @Sendable () async throws -> FactorSecret
    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
        try await Task.detached(priority: .userInitiated) {
            try SecureEnclaveFactor.sharedSecret(keyID: keyID, ephemeralPublicKey: ephemeralPublicKey,
                                                 directory: directory, reason: "Eintrag aufdecken")
        }.value
    }
    func cardSecret() async throws -> FactorSecret { try await scanCard() }          // QRScanner, jedes Mal neu
    func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret {
        guard let device else { throw SiegelError.factorUnavailable(.securityKey) }
        return try await Task.detached(priority: .userInitiated) {
            try SecurityKeyFactor.secret(on: device, credentialID: credentialID, salt: salt)
        }.value
    }
}
```

**Sicherheitsschlüssel wählen:** `SecurityKeyFactor.connectedDevices()` (Name = Hersteller/Produkt). Kein Gerät →
Stufe 5 bleibt auswählbar, das Einrichten verlangt aber eines (§13). Solange `SecurityKeyFactor.testedWithHardware`
false ist, `SecurityKeyFactor.hardwareNotice` („Mit echter Hardware ungetestet“) neben der Stufe zeigen.

**Signatur:** beim Start `CodeSignatureCheck.mainBundleIsValid()` (in `AppModel.production(signatureIsValid:)`, als
Erstes, synchron); false → `BlockReason.signatureInvalid`, kein Entsperren, Meldung „Siegel ist beschädigt – Die App
wurde verändert oder ist beschädigt. Bitte neu installieren.“ Ausserhalb eines `.app`-Bündels (`swift run`, Tests) →
true.

## Selbstvernichtung (v4.3, SPEC §23.1)

- **`SecureEnclaveFactor.destroy(keyID:directory:)`** – Krypto-Löschung einer Schlüsseldatei (gedacht für den
  Vernichtungs-Schlüssel V, geht aber für jede `<keyID>.siegelhw`): Inhalt an Ort und Stelle mit Zufallsbytes
  (`arc4random_buf`, Blöcke à 4 KiB, ganze Länge) überschreiben, `F_FULLFSYNC` (sonst `fsync`), `unlink`, Ordner
  `fsync`. Kein Dialog, kein Finger, kein DEK – läuft auch gesperrt und auf dem Main-Thread (wenige KiB).
  - Fehlt die Datei → kein Fehler (wiederholbar). Ein Symlink an ihrer Stelle wird nie durchschritten (`O_NOFOLLOW`):
    nur der Link wird gelöscht, das Ziel bleibt unberührt. Nur reguläre Dateien werden überschrieben.
  - Scheitert nur das Überschreiben, wird trotzdem gelöscht (kein Fehler); scheitert das Löschen → `io("hw.destroy")`.
  - Die Oberfläche nutzt es über `FactorHardware.destroySecureEnclaveKey`, wenn ein eben angelegter V nicht übernommen
    wurde (Schreiben gescheitert, gesperrt). Bei einem Auslöser ruft der **Kern** es über seine austauschbare Schicht
    `store.destructionKeyEraser` (die Oberfläche setzt `ClosureDestructionKeyEraser { hw.destroySecureEnclaveKey… }`,
    Integration v4.3); liegt die Datei danach noch da, überschreibt und löscht der Kern sie selbst
    (`FileDestructionKeyEraser`, gleiches Verfahren). SiegelCore hängt nicht von SiegelHardware ab.
  - V wird wie ein Eintrags-Schlüssel angelegt (`enrollEntryKey`, kind Einträge, `.biometryCurrentSet`); der Kern ruft
    `secureEnclaveSharedSecret(keyID: vKeyID, …)` für vernichtbare Einträge – kein eigenes kind nötig.
  - Im Hardware-Ordner liegen neu (vom Kern) `zustand.json` und die Ablage des Vernichtungs-Passworts
    (`<fileID>.siegelhw`, 2048 B, Form einer kind-2-Datei). Beide nie als „verwaist“ aufräumen. Die SE-Schlüsseldateien
    werden bewusst **nicht** auf 2048 B gepolstert (SPEC §12, v4.3: `zustand.json` nennt die Ablage ohnehin).
- **Backup-Ausschluss**: Jede Schlüsseldatei (Entsperren, Einträge, V) bekommt `isExcludedFromBackup = true` – gesetzt
  auf der Temp-Datei, bevor Daten darin stehen, und vor dem Umbenennen; scheitert es, bleibt nichts liegen
  (`io("hw.write")`). Geprüft wird das Attribut nach dem Setzen.
- Tests (`Tests/SiegelHardwareTests/VernichtenTests.swift`, nur Software-Schicht): Attribut an allen Arten, Überschreiben
  vor dem Löschen (zweiter harter Link auf denselben Inode sieht danach Zufall gleicher Länge, kein Magic, kein Blob),
  danach `factorUnavailable` ohne Touch-ID-Abfrage, nur dieser Schlüssel betroffen, fehlende Datei, Symlink,
  ganze Datei über Blockgrenzen, Löschen ohne Schreibrecht → `io("hw.destroy")`.
- Ehrliche Grenzen (für SICHERHEIT.md): Auf einer SSD und unter APFS (Kopie beim Schreiben, **lokale Time-Machine-
  Schnappschüsse** des ganzen Volumes, die den Backup-Ausschluss nicht beachten, bis etwa 24 h) kann der alte Blob
  physisch liegen bleiben. Er ist nur mit der Secure Enclave dieses Macs und dem Finger nutzbar. Schlüsseldateien,
  die vor v4.3 geschrieben wurden, haben das Attribut noch nicht (nur neue bekommen es; V ist immer neu).

## Berechtigungen (Bau-Agent)

- `com.apple.security.device.camera` + `NSCameraUsageDescription` (z. B. „Siegel liest deine QR-Schlüsselkarte. Bilder
  werden nicht gespeichert.“). Ohne Info.plist-Text beendet macOS die App beim ersten Kamerazugriff.
- `com.apple.security.device.usb` für den Sicherheitsschlüssel (IOHIDDeviceOpen in der Sandbox).
- Kein Schlüsselbund-Entitlement: Der SE-Schlüssel liegt als Blob in der eigenen Datei (§14.1).

## Ehrlicher Stand

- **Secure Enclave:** Logik vollständig gegen eine Software-Schicht getestet (gleiche P-256-Rechnung, Fehler wie
  Abbruch/geänderte Biometrie nachgestellt); `swift test` löst nie Touch ID aus. Mit echter Hardware wurde nur
  `isAvailable` und das Erzeugen eines Schlüssels ohne Nutzung geprüft (`SIEGEL_HW_MANUELL=1 swift test --filter
  Manuell`). Einrichten/Entsperren mit Touch ID gehört in PRUEFLISTE.md (auch: Finger hinzufügen → Schlüssel
  unbrauchbar → Notfallweg).
- **FIDO2:** eigene CTAP2-Umsetzung, gegen einen virtuellen Authenticator nach CTAP 2.1 getestet (beide
  PIN/UV-Protokolle, CTAP 2.0 ohne Protokoll-Liste, PIN gesetzt, alwaysUv, eingebaute UV, Ablehnen, keine Berührung,
  kaputte und beschädigte Antworten, Fuzz). **Mit echter Hardware ungetestet** (`testedWithHardware = false`). Die
  Attestation und die Assertion-Signatur werden bewusst nicht geprüft: Es gibt keinen Dienst, dem sie etwas beweisen
  müssten; eine falsche hmac-secret-Ausgabe ergibt einfach einen falschen Schlüssel (`wrongPassword`).
- **Kamera:** in Tests nie gestartet; die Erkennung ist mit erzeugten QR-Bildern durch Vision getestet (auch über die
  Pipeline des Scanners mit einem `CVPixelBuffer`).
- Für den Fuzzer (`SiegelFuzz`, §21) sind die Parser `package`-sichtbar: `CBORDecoder.decode`,
  `CTAPHID.Reassembler.feed`, `AuthenticatorData.parse`, `AuthenticatorInfo.parse`, dazu `FIDO2Flows` mit eigenem
  `CTAPHIDTransport`.
