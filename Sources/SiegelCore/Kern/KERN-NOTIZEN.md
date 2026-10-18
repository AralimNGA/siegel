# Kern – Notizen (Stand nach Stufe B + Selbstvernichtung v4.3)

Stand 17.10.2026. Stufe A: §13 Format v2 + Mehrfaktor, §15 Shamir, §22 ohne §16/§17. Stufe B: §16 Eintrags-Schutz,
§17 Offline-Bericht, §18 TOTP als Geheimteil, §19 KeePass-Export (Aufruf), Exporte nach Schutz. **v4.3: §23
Selbstvernichtung** (Abschnitt ganz unten). **v4.4:** Krypto-Befunde der zweiten Prüfung (Vernichtungs-Passwort an die
Faktoren gebunden, DEK-Rotation nach einer Vernichtungs-Sitzung, reuseTag nach §1.1). **v4.5:** Fuzz-Befunde
vernichtung-1 bis -8 (Zustand, der den Entsperr-SE-Schlüssel nennt, gilt nicht – auch ohne lesbaren Kopf und beim
Vermerk; keine Ablage-Bereinigung von Schlüsseln in Gebrauch; Ablage ersetzt nur eine Ablage; unbrauchbare Uhr;
`io("destruction.write")`). Alle Tests grün (Stand 17.10.2026 abends: SiegelCoreTests 369 in 56 Suiten, davon 27 in
den fünf Suiten „Selbstvernichtung: …“, 11 in den drei Suiten „Krypto-Befunde: …“ und 9 in „Fuzz-Befunde:
Selbstvernichtung“; SiegelHardwareTests 114; SiegelAutofillTests 13).

## Dateien

| Datei | Inhalt |
|---|---|
| `VaultFile.swift` | Format v1 + v2: `FileFormat` (Labels je Version, Prüfsumme mit Label „Siegel v<n> file check“ nach Byte 6–7), `HeaderFactorFields`, `VaultHeader` (v1-Init, v2-Init mit Prüfung, `rebuilt`, strenger `parse`, `info`), `VaultSlots`, `VaultFile` |
| `FactorKDF.swift` | §13.1: `FactorKDF` (e/c/y, `precheck` = factorMissing/wrongCard vor Argon2, `kek`, `deriveKEK`, `fidoCheck`), `EntryKeyDerivation` (Hybrid-pk aus q bzw. y2), `KEKCache` (cacht p = Argon2-Ausgabe) |
| `CardCode.swift` | §14.2/§22 öffentlich: Format, Prüfsumme, Kennung |
| `Shamir.swift` | §15: `GF256` (zeitkonstant), `Shamir` (split/combine, Format 56 Zeichen, Kandidaten pro Teil, `searchPair`) |
| `RecoveryKEM.swift` | §1.3 Kombinierer; dazu (B) Kombinierer/Kapseln **mit Zusatzfeld** (16 B nach dem Label), `privateKeys(ikm:…expected:)`, generisches `decapsulate` |
| `EntrySealing.swift` | (B) §16.1 Kryptografie: Versiegeln, Freigabe über den Provider, Öffnen, Notfall-Umschläge, Notfall-Gruppen + Anker, Geheimteil-JSON, reuseTag/Metadaten |
| `VaultContent.swift` | Inhalts-JSON v2 (Stufe, Faktor-Teile, TOTP, Schutz; (B) `entryKey`, `recoveryGroups`, pro Eintrag `sealed` + `meta`), liest v1 und Stufe-A-Inhalte |
| `VaultContent+Schutz.swift` | (B) Versiegeln eines Eintrags, Gruppen, `unsealAll(r:)`, Export über Gruppen, Kit-Neukapselung, `prepareEntryData`, Konsistenzregeln `checkSealing` |
| `VaultStore.swift` | Speichern (§4), Sicherungen, `hardwareDirectory`, `removeHardwareKey`; `persist` ruft `prepareForSave` + `prepareEntryData` |
| `VaultStore+Zugang.swift` | create, inspect, unlock (mit Faktoren), restore/import (mit Faktoren), `rekey`, `install` |
| `VaultStore+Notfall.swift` | Code/Teile prüfen, recover (Code/Teile) – (B) entsiegelt vorher alles (`unsealed(_:r:)`) –, Notfallweg über Sicherungen |
| `UnlockedVault.swift` | Zustand, Einträge (B: upsert-Regeln, Import mit Versiegeln), verify, Passwortwechsel, `save`, `verifyAccess`, `reuseSet` |
| `UnlockedVault+Notfall.swift` | prepare/commit Kit (beide Schemata; B: Gruppen ans neue Kit), bestehendes Kit bestätigen, purge |
| `UnlockedVault+Stufen.swift` | `enrollFactors`, `changeSecurityLevel` (B: Gruppen ans neue Kit, Ersatz-Sperre), `planFactors` |
| `UnlockedVault+Schutz.swift` | (B) `revealSecrets`, `setProtection`, `securityReport`, async-Varianten (Kit, Stufe, Exporte), `exportCSV`, `exportKeePass`, `EntrySecrets.replacingPassword` |
| `Selbstvernichtung.swift` | (v4.3) öffentliche Typen §23.3: `DestructionTrigger`, `DestructionSettings`, `DestructionStatus`, Schicht `DestructionKeyEraser` (+ `ClosureDestructionKeyEraser`, Rückfall `FileDestructionKeyEraser`) |
| `DestructionState.swift` | (v4.3) `DestructionConfig` (im Inhalt), `DuressCrypto` (d → Schlüsselpaar, Umschlag), `DuressFile` (Ablage `.siegelhw`), `DestructionState` (`Hardware/zustand.json`) |
| `VaultStore+Vernichtung.swift` | (v4.3) `destructionStatus()`, `checkDeadman(now:)`, Vernichten, Zähler, echtes/Vernichtungs-Entsperren vermerken, Abgleich nach jedem Speichern, beide Argon2 parallel (`ParallelKDF`) |
| `UnlockedVault+Vernichtung.swift` | (v4.3) `configureDestruction` (sync + async), `removeDestroyedEntries`, `destroyedEntries`, Lese-Zusätze, `CachingEntryFactors` |
| `VaultContent+Vernichtung.swift` | (v4.3) `sealDestructible(at:)`, `replaceSecrets(at:with:)` |

## Format v2 (§13.2) – was im KOPF steht

`magic ‖ version=2 ‖ vaultID ‖ kdfAlg ‖ ops ‖ mem ‖ kdfSalt ‖ factorMask ‖ recoveryScheme ‖ seKeyID[16] ‖ cardTag[4] ‖
credLen u16 ‖ credentialID ‖ fidoSalt[32] ‖ pkM ‖ pkX`, ungesetzte Felder Nullbytes. Offsets: Maske 53, Schema 54,
seKeyID 55, cardTag 71, credLen 75, Credential ab 77.

Labels v2: „Siegel v2 slot pw / slot rec / payload / file check / hybrid KEM“. **Abweichung von §13.2 (Stufe A):**
„recovery checksum“ und „kit id“ bleiben „Siegel v1 …“ (gehören zum gedruckten Kit; v1-Codes bleiben nach der Migration
gültig).

Invariante: `content.level.factors == header.factors` (lesen → `corruptFile("payload.level")`, schreiben →
`crypto("level.mismatch")`). Das Notfall-Schema im Kopf beschreibt das **Kit**, nicht die Stufe.

## Inhalt (Klartext-JSON v2, sortierte Schlüssel, null explizit)

```json
{ "entries": [ { "created", "deletedAt", "history": [...], "id", "meta": {"changed", "strength", "tag"},
                 "modified", "notes", "password", "protection": 1…5,
                 "sealed": null | { "blob": {"card": null|{ctM,ctX}, "ct", "fido": null|{ctM,ctX}, "nonce", "se": null|b64(65)},
                                    "recovery": {"ctM", "ctX", "key": b64(72)} },
                 "title", "totp", "url", "username" } ],
  "entryKey": b64(32),
  "factors": { "card": …|null, "secureEnclave": …|null, "securityKey": …|null },
  "level": 1…5, "recoveryConfirmedAt": …|null,
  "recoveryGroups": [ { "anchor": {blob wie oben}, "id", "kit": {"ctM","ctX","key"}, "mask": 1|3|7, "pkM", "pkX" } ],
  "savedAt": …, "v": 2 }
```

`v` bleibt 2 (nur Felder dazu). Stufe-A- und v1-Inhalte ohne `entryKey`/`meta`/`sealed`/`recoveryGroups` werden gelesen;
der Grundschlüssel entsteht beim Entsperren im Speicher und wird mit dem nächsten Speichern geschrieben, Metadaten
offener Einträge ebenso (`prepareEntryData`).

Im Speicher: `VaultContent.sealed: [UUID: SealedSecrets]`, `meta: [UUID: EntryMeta]`, `recoveryGroups`, `entryKey`.
Versiegelte Einträge haben in `entries` leere password/notes/totp/history und `secretsSealed = true` (gesetzt beim
Dekodieren aus `sealed != nil`).

**Konsistenz** (`checkSealing`, beim Lesen `corruptFile`, beim Kodieren `crypto` – Programmfehler werden nie
geschrieben): Schutz 1 ⇔ offen ohne `sealed`; Schutz ≥ 2 ⇔ `sealed` mit genau den Faktor-Teilen der Maske, leeren
Klartextfeldern, `meta`, eingerichteten Faktoren und einer Gruppe für die Maske; Gruppen eindeutig pro Maske
(1, 3, 7), wohlgeformt; reuseTag 16 B; keine doppelten Kennungen, sobald etwas versiegelt ist.

## Eintrags-Schutz (§16.1) – wie gebaut

```
base   = HKDF-SHA512(EBK, salt = entryID, info = "Siegel v2 entry dek", 32)        EBK = entryKey im Inhalt
ss_se  = HKDF-SHA512(ECDH(k, seEntryPub), salt = entryID, info = "Siegel v2 entry se", 32)   k ephemer, Software-P256
ss_card/ss_fido = SHA3-256(label ‖ entryID ‖ ssM ‖ ssX ‖ ctX ‖ pkX ‖ SHA3(ctM) ‖ SHA3(pkM)),
                  label "Siegel v2 entry card" / "Siegel v2 entry fido", an cardPK/fidoPK (aus q bzw. y2)
K      = HKDF-SHA512(base ‖ [ss_se] ‖ [ss_card] ‖ [ss_fido], salt = entryID, info = "Siegel v2 entry key" ‖ s ‖ M, 32)
blob   = XChaCha20-Poly1305(K, sodium_pad(JSON{history,notes,password,totp}, 256),
                            AD = "Siegel v2 entry" ‖ vaultID ‖ entryID ‖ s ‖ M)
```

**Abweichung 1 – Grundschlüssel statt DEK:** §16.1 nimmt `HKDF(DEK, …)`. Der DEK wird aber bei jedem Zugangswechsel
neu gezogen (§1.2: Passwort, Stufe, Kit, Sicherung, Notfall); jedes K wäre danach falsch, und neu versiegeln ginge nur
mit allen Faktoren aller Einträge. Darum ein eigener, stabiler 32-Byte-Grundschlüssel `entryKey` im verschlüsselten
Inhalt. „Das Passwort bleibt immer nötig“ gilt unverändert (EBK liegt nur im mit dem DEK verschlüsselten Inhalt).

**Abweichung 2 – Notfall-Umschlag über Gruppen:** §16.1 kapselt pro Eintrag direkt an pkM/pkX des Kits. Dann wäre
nach jedem neuen Kit (commitRecovery, Stufenwechsel 3↔4) jeder versiegelte Eintrag mit dem neuen Code unlesbar
(die App kennt R nicht und kann ohne die Faktoren nicht neu kapseln). Darum:
- Pro Faktormaske M (Schutz 2/3 → {SE}, 4 → {SE, Karte}, 5 → alle) eine **Notfall-Gruppe**: ERS = 32 Zufallsbyte,
  Hybrid-Schlüsselpaar daraus (`"Siegel v2 entry recovery ML-KEM-1024 seed"` / `"… X25519"`).
- Umschlag pro Eintrag: K hybrid an das Gruppen-pk gekapselt (Label `"Siegel v2 entry recovery"`, entryID als
  Zusatzfeld), AD `"Siegel v2 entry recovery" ‖ vaultID ‖ entryID ‖ s ‖ M`.
- `kit`: ERS hybrid an pkM/pkX des Kopfes (Label `"Siegel v2 entry recovery kit"`, Gruppen-ID als Zusatzfeld) →
  der Notfallcode öffnet alles (R → Kit → ERS → Umschläge → K → Blob).
- `anchor`: ERS wie ein Eintrag unter den Faktoren von M versiegelt (s = 0, AD-Label `"Siegel v2 entry anchor"`).
  Bei einem **neuen Kit** wird pro gebrauchter Gruppe der Anker freigegeben (eine Freigabe je Gruppe: Schutz 2/3 ein
  Touch ID, 4 + Karte, 5 + Schlüssel) und nur `kit` neu gekapselt. Ohne Freigabe kein neues Kit (`factorMissing`).
- Ungebrauchte Gruppen fallen beim Speichern weg; neue entstehen beim ersten Versiegeln einer Maske (nur
  öffentliche Schlüssel nötig).

**Ehrliche Grenze dazu (für SICHERHEIT.md):** Wer den entsperrten Mac übernommen hat und eine Freigabe gegen den
Anker einer Gruppe tauschen kann, bekommt mit einer Berührung alle Einträge dieser Maske (statt nur einen). Gegen
Dateidiebstahl ändert sich nichts.

### Regeln (öffentliche API)

- `upsert`: neue Einträge bekommen mindestens `policy.defaultEntryProtection` (Stufe 4/5: Schutz 2), Schutz ≥ 2 wird
  sofort versiegelt (fehlender Eintrags-Faktor → `factorMissing`, nichts geschrieben). Versiegelter Bestand: nur offene
  Felder; `secretsSealed` muss gesetzt, Geheimteile leer, Schutz gleich sein (`io("entry.sealedSecrets")`,
  `io("entry.protection")`). Offener Bestand darf höher geschützt werden, nie tiefer. Kopie mit `secretsSealed`, deren
  Bestand offen ist oder die neu ist → `io("entry.stale")`.
- `setProtection(p, id, secrets)`: einziger Weg, Geheimteile versiegelter Einträge zu ändern (auch Verlauf leeren);
  `secrets` ersetzt ganz, Verlauf nach §3 gekürzt. `EntrySecrets.replacingPassword(with:)` schiebt das alte Passwort
  in den Verlauf. `clearHistory` bei versiegelten Einträgen → `io("entry.sealedSecrets")`.
- `revealSecrets(id:factors:)` (`@concurrent`): Schutz 1 ohne Provider; sonst Provider Pflicht, nur die Methoden der
  Maske, je einmal; falsche Karte `wrongCard` (Kennung + pk-Prüfung), falscher SE/Schlüssel `wrongPassword`, Abbruch
  `factorCancelled`, fremde Fehler `factorUnavailable(kind)`, Sperren während der Freigabe `io("vault.locked")`.
- Eintrags-Faktor ersetzen (anderer Eintrags-SE-Schlüssel, andere Karte, anderer Sicherheitsschlüssel), solange
  versiegelte Einträge daran hängen → `notAllowedAtLevel` (enrollFactors und changeSecurityLevel).
- Notfall (`recover`, `recoverFromNewestReadableBackup`): erst `unsealAll(r:)`, dann Wiederverwendungsprüfung, dann
  `resetAfterRecovery()` (wirft, falls noch etwas versiegelt wäre). Jedes Scheitern nach der Kit-Prüfung →
  `corruptFile("entry.recovery")`; der Sicherungsweg probiert dann die nächste Sicherung.
- Neues Kit: sync `commitRecovery` / `changeSecurityLevel` werfen `factorMissing`, wenn versiegelte Einträge da sind;
  die async-Varianten mit `entryFactors:` holen die Anker-Freigaben (beim Stufenwechsel erst nach der Argon2-Prüfung).

## Offline-Bericht (§17)

- `meta` pro Eintrag: `tag` = `crypto_generichash(key: HKDF(EBK, "Siegel v2 reuse tag"), OpaqueString(password))[0..<16]`
  (v4.4: Zs → U+0020, dann NFC – dieselbe Abbildung wie das Master-Passwort; bis v4.3 nur NFC, dann passte der Tag eines
  Passworts mit U+00A0 nie zum Master-Tag). Alte Tags: offene Einträge beim nächsten Speichern neu, ohne neues
  Änderungsdatum (`EntrySealing.meta` vergleicht auch mit `legacyReuseTag`); versiegelte erst beim Neu-Versiegeln, bis
  dahin prüft der Kern zusätzlich den alten Tag der rohen Master-Eingabe (`masterReuseTags(_:raw:)`, Entsperren,
  Passwortwechsel, Sicherung einsetzen; CSV-Import ebenso),
  `strength` = zxcvbn-Stufe, `changed` = letzte Passwortänderung. Offene Einträge: `prepareEntryData` bei jedem
  Speichern (Stärke nur neu, wenn sich der Tag ändert); versiegelte: beim Versiegeln. Ohne Metadaten gilt der jüngste
  Verlaufseintrag bzw. `created`, beim Import `modified`.
- **Abweichung:** Schlüssel aus EBK statt DEK (sonst wären Tags nach jeder DEK-Rotation unvergleichbar).
  „Gleich wie Master“ wird nicht als Flag gespeichert (wäre nach einem Passwortwechsel falsch), sondern über
  `masterReuseTag` (Tag des Master-Passworts, im Zustand) gerechnet; offene Einträge zusätzlich wie bisher über den
  Master-Tag (inkl. Verlauf). `changeMasterPassword` lehnt auch versiegelte Treffer ab.
- `securityReport()`: weak = Stufe < fair (< 36 Bit), reused = gleicher Tag (Gruppen ≥ 2, Listenreihenfolge),
  old = > 365 Tage, sameAsMaster, total = nicht gelöschte Einträge mit Passwort.
- Ehrlich: Wer das Master-Passwort (+ Öffnungsfaktoren) hat, aber nicht die Eintrags-Faktoren, kann Vermutungen für
  geschützte Passwörter über den Tag schnell prüfen (wie in §17 angelegt) und sieht deren Stärke-Stufe.

## Exporte

- `exportCSV` / `exportKeePass`: Stufe 4/5 → `notAllowedAtLevel` (vor Argon2); KeePass: Export-Passwort nach
  `MasterPasswordPolicy` (`passwordTooWeak`), ≠ Master (`masterPasswordReused`), beides vor Argon2. Schutz 4/5 fehlt
  immer; versiegelte Schutz-2/3-Einträge über die {SE}-Gruppe (eine Freigabe, nach der Passwortprüfung) – sync →
  `factorMissing`. Ordner `Siegel-Export-<Datum>.noindex` 0700, Datei 0600 (`.csv` bzw. `.kdbx`), vom Backup
  ausgenommen; Daten erst vollständig erzeugen, dann schreiben (bei Exporter-Fehler bleibt nichts liegen).
- `KeePassExport.kdbx(items, password:)` bekommt `(VaultEntry mit eingesetzten Geheimteilen, EntrySecrets)`.
  Testschalter `TestHooks.keePassExporter`.

## Sperren und Speichern

- `writeLock` serialisiert Änderungen, `stateLock` nur kurz für `snapshot()`/`commit()`. Muster:
  `mutate { content, now, header in … }` (Kopf = beim Entsperren authentifiziert, für vaultID und Kit).
- async-Methoden (`@concurrent`): erst `snapshot()`, Provider-Aufrufe ohne Lock, danach der sync-Kern unter
  `writeLock` (prüft erneut). Nie über ein `await` hinweg einen Lock halten.
- Zugang prüfen: `verifyAccess(pw, factors, s)`. Neuer Zugang: `store.rekey(…)` + `store.persist(…)`.
- Stufen-KDF: `store.limits.profile(for:)` (Testschalter: Standard 8 KiB/t1, Stark 16 KiB/t2;
  `TestHooks.levelKDFOverride` für Fixtures).

## Tests (Hilfen)

`KernStufen.make(level)`, `KernFaktoren` (Zufallsmaterial wie vom Hardware-Modul), `KernMigrationTests.writeV1`,
`KernBeispielDateiV2` (Fixture-Konstanten). Stufe B: `SchutzProvider` (Software-P256 statt Secure Enclave, feste q/y2,
Aufrufzähler, Fehlverhalten pro Faktor), `SchutzTresor.make(level, enroll:)`, `schutzEntry(…)`,
`KernBerichtTests.padded(json)` (Polsterung wie `sodium_pad` für handgebaute Inhalte). Testvektoren der
Eintrags-Kryptografie (base, ss_se, K, reuseTag, Kombinierer mit entryID) in `KernSchutzVektorTests`, mit Python
(`hmac`/`hashlib`) nachgerechnet – Grundlage für die Python-Referenz (§21).

## Selbstvernichtung (§23, v4.3) – wie gebaut

### Kryptografie und Ablage

```
Vernichtbarer Eintrag (nur Schutz 4/5, nur Stufe 4/5), statt Eintrags-SE-Schlüssel der Vernichtungsschlüssel V:
  ss_v = HKDF-SHA512(ECDH(k, vPub), salt = entryID, info = "Siegel v2 entry destruction", 32), k ephemer (Feld "se")
  K    = HKDF-SHA512(base ‖ ss_v ‖ ss_card ‖ [ss_fido], salt = entryID, info = "Siegel v2 entry key destructible" ‖ s ‖ M)
  Blob = XChaCha20-Poly1305(K, …, AD = "Siegel v2 entry destructible" ‖ vaultID ‖ entryID ‖ s ‖ M)
  kein Notfall-Umschlag, keine Notfall-Gruppe:  "sealed": {"blob": {…}, "recovery": null}
Vernichtungs-Passwort:
  d      = Argon2id(pw_d, dSalt (16 B), Parameter des Kopfes)
  pk_d   = Hybrid(HKDF(d, salt = vaultID, "Siegel v2 duress ML-KEM-1024 seed" / "Siegel v2 duress X25519"))
  check  = HKDF-SHA512(d, salt = vaultID, "Siegel v2 duress check", 16)
  F      = HKDF-SHA512(e ‖ c ‖ [y] (Faktor-Schlüssel §13.1), salt = vaultID, "Siegel v2 duress factors" ‖ mask, 32)   (v4.4)
  kek    = HKDF-SHA512(Kombinierer §1.3 (Label "Siegel v2 duress", Zusatzfeld fileID) ‖ F, salt = fileID,
                       "Siegel v2 duress kek", 32)                                                                (v4.4)
  Umschlag = XChaCha20-Poly1305(kek, DEK, AD = "Siegel v2 duress" ‖ vaultID ‖ fileID ‖ dSalt)
```

**v4.4 – Bindung an die Faktoren:** Bis v4.3 war `kek` die Kombinierer-Ausgabe allein; Container-Kopie und
Vernichtungs-Passwort lieferten offline den DEK (Liste, Metadaten, alle Einträge mit Schutz 1), in Stufe 4/5 also ein
zweites Master-Passwort ohne Faktoren. Jetzt braucht der DEK zusätzlich F. Der Prüfwert hängt weiter nur an d (erkannt
und vernichtet wird auch bei falschem Faktor; dann `wrongPassword`). Die Sitzung hält F (`State.duressBinding`, aus den
Faktoren beim Entsperren bzw. beim Stufenwechsel neu); `persist(…duressBinding:)` wirft `crypto("duress.binding")`, wenn
ein Inhalt mit Vernichtungs-Passwort ohne F geschrieben werden soll.

- Inhalt (massgeblich): `"destruction": {"duress": null|{"check","fileID","pkM","pkX","salt"}, "settings":
  {"deadmanDays","duressEnabled","maxFailedAttempts"}, "vKey": null|{"keyID","publicKey"}}`. **Abweichung von „null
  explizit“:** Ohne Selbstvernichtung fehlt der Schlüssel ganz (Inhalte ohne §23 bleiben bytegleich wie bisher).
  Im Speicher: `VaultContent.destructible: [UUID: SealedBlob]` (eigene Tabelle neben `sealed`), `destruction`.
- `Hardware/<fileID>.siegelhw` (Vernichtungs-Passwort, 2048 B, vom Backup ausgenommen): Form der SE-Schlüsseldateien
  des Hardware-Moduls – `"SIEGELHW"` ‖ v1 ‖ kind 2 ‖ fileID ‖ blobLength 1922 ‖ blob ‖ zufälliger gültiger P-256-Punkt ‖
  SHA3-256("Siegel v2 hw file check" ‖ …); blob = dSalt ‖ check ‖ ctM ‖ ctX ‖ wrap ‖ Zufall. Bei **jedem** Speichern
  neu gekapselt (frisch, gleicher Name; ersetzt wird nur eine Datei mit der Form einer Ablage – Länge, magic, kind 2,
  Bloblänge 1922 –, nie ein SE-Schlüssel oder V unter diesem Namen, Fuzz-Befund vernichtung-8; eine beschädigte oder
  fremde Ablage heilt so weiter) – damit folgt der Umschlag jeder DEK-Rotation ohne Passwort (Passwortwechsel,
  neues Kit, Stufe, Sicherung einsetzen) und die Schreibmuster von echter und Vernichtungs-Sitzung sind gleich. Seit v4.4
  auch bei jedem echten Entsperren (ersetzt ungebundene Ablagen aus v4.3, die nur noch „erkannt“ liefern).
- `Hardware/zustand.json` (0600, vom Backup ausgenommen, streng gelesen – Schema, Version, Bereiche; JSONDecoder
  übergeht dabei ungültiges UTF-8 und rohe Steuerzeichen in Werten unbekannter Schlüssel, ohne Wirkung –, atomar
  geschrieben):
  `{"destroyed": null|{"at","keyID","trigger"}, "duressFileID", "failedAttempts", "lastGenuineUnlock",
  ["rekeyPending": true,] "settings", "v": 1, "vaultID", "vKeyID"}` (`rekeyPending` v4.4, nur solange nach einer
  Vernichtungs-Sitzung die DEK-Rotation aussteht; ältere Dateien ohne den Schlüssel bleiben gültig). Die Einstellungen werden nach jedem Speichern und jedem echten Entsperren aus dem
  Inhalt nachgeführt; ein Vermerk gilt nur, solange der Inhalt genau dieses V nennt. Andere vaultID → gilt nicht.
  Ohne Selbstvernichtung gibt es die Datei nicht.

### Abläufe

- **Entsperren** (`unlock`): zuerst `checkDeadman`. Mit Vernichtungs-Passwort: Faktoren-Vorprüfung, dann Argon2 für
  das Master-Passwort (dieser Thread) und für d (eigener Thread) **gleichzeitig**; scheitert einer mit `kdfFailed`
  (Speicher), beide nacheinander. Fehlt die Ablage, läuft das zweite Argon2 mit Wegwerf-Salz (gleiche Dauer).
  Master passt → echt. Sonst Prüfwert passt → V vernichten (synchron), DEK aus dem Umschlag (mit F), Sitzung mit
  `isDuressSession`, Vermerk `rekeyPending`. Sonst `wrongPassword` (+ Zähler). Veralteter Umschlag (Schreibfehler) oder
  falscher Faktor → vernichtet, aber `wrongPassword`.
- **Rotation nach einer Vernichtungs-Sitzung** (v4.4): Steht `rekeyPending` an, erneuert das nächste echte Entsperren
  zuerst DEK und Salz (`rekeyAfterDuress`: `rekey` mit Stufe, Faktoren, Kit, KDF des Kopfes + `persist(newDEK: true)`,
  ein Argon2 mehr) – nicht bei Rollback-Verdacht; scheitert es, öffnet der Tresor wie bisher und der Vermerk bleibt.
  Jedes `persist(newDEK: true)` (Passwort, Stufe, Kit, Sicherung, Notfallweg, Vernichtungs-Passwort ändern) löscht den
  Vermerk. Das Vernichtungs-Passwort bleibt eingerichtet (wiederholter Zwang); offline hilft es nur mit F.
- **Vernichten**: `destructionKeyEraser.destroy(keyID:directory:)` (App: SiegelHardware), liegt die Datei danach noch
  da → `FileDestructionKeyEraser` (Zufallsbytes, `F_FULLFSYNC`, `unlink`, Ordner `fsync`); dann Vermerk
  `destroyed {keyID, trigger, at}`. Spätere Prüfungen wiederholen nur das Löschen, falls die Datei wieder/noch da ist.
  Jeder Fehler beim Schreiben von zustand.json bzw. der Ablage ist `io("destruction.write")` (Fuzz-Befund
  vernichtung-5: ein nicht beschreibbarer Hardware-Ordner lieferte `io("file.create")`); V ist dann trotzdem
  überschrieben, und ohne Vermerk wiederholt die nächste Prüfung das Vernichten.
- **Vernichtungs-Passwort erkannt** (`recordDuressUnlock`): liest wie alle Prüfungen im gesperrten Zustand über
  `currentState()`. Wird zustand.json zwischen Probe und Vermerk getauscht und gilt dann nicht (fremde vaultID,
  nennt den Entsperr-SE-Schlüssel), wird nichts vermerkt und nichts gelöscht (Fuzz-Befund vernichtung-4).
- **Totmann**: `checkDeadman(now)`: vernichtet bei `now ≥ letzte echte Entsperrung + D`; `now < letzte − 1 Tag`
  (Uhr rückwärts) → nichts, nichts geschrieben; ebenso eine unbrauchbare Uhr (±∞, NaN; Fuzz-Befund vernichtung-3). Echtes Entsperren setzt `lastGenuineUnlock = max(alt, jetzt)` – bei
  zurückgestellter Uhr bleibt der alte Wert (nicht verlängert, und später keine falsche Vernichtung).
- **Zähler**: nur `wrongPassword` beim Entsperren und auf den Sicherungswegen (`restoreBackup`, `importBackup`,
  `restoreNewestReadableBackup` – sonst liesse er sich über sie umgehen). Nicht: `kdfFailed`, fehlende Faktoren,
  falsche Karte, das Vernichtungs-Passwort. Echtes Entsperren und Einsetzen einer Sicherung setzen ihn zurück; das
  Vernichtungs-Passwort auch (wirkt normal). Bei N: vernichten, trotzdem `wrongPassword`. Zähler aus → nichts geschrieben.
- **Markieren/Entmarkieren** (`configureDestruction`): die ganze Auswahl wird übergeben. Neu versiegelt werden muss
  mit den Geheimteilen: neu markierte über ihre Notfall-Gruppe (eine Freigabe je Gruppe), entmarkierte über V (je
  Eintrag; Karte/Schlüssel werden pro Aufruf nur einmal geholt, `CachingEntryFactors`). Die synchrone Variante aus
  §23.3 geht nur, wenn nichts neu zu versiegeln ist (sonst `factorMissing(.secureEnclave)`), die async-Variante mit
  `entryFactors:` ist der normale Weg. **Neu markiert → danach `purgeBackups`** (ältere Sicherungen enthielten die
  Einträge noch mit Notfall-Umschlag); Rückgabe `PurgeReport?` (`@discardableResult`, nil = nichts entfernt).
  **Vernichtungs-Passwort ersetzt oder entfernt → neuer DEK** (`rekeyAndSave`, v4.4; der Umschlag war ein Schlüssel-Slot,
  §1.2). Nur Einstellungen ändern behält DEK und Ablage.
- **Notfallcode** (`recover`, Notfallweg über Sicherungen): vernichtbare Einträge fallen ganz weg (kein Notfallweg,
  wie beim Markieren angekündigt), die Selbstvernichtung ist danach aus. V bleibt liegen (ältere Sicherungen).
- **Nach der Vernichtung** (echte Sitzung): `destroyedEntries` = vernichtbare Einträge; sie bleiben in `entries`,
  `revealSecrets` → `factorUnavailable(.secureEnclave)` ohne Provider-Aufruf, `setProtection` →
  `io("entry.destroyed")`, `configureDestruction` → `io("destruction.destroyed")`. `removeDestroyedEntries()` entfernt
  sie und schaltet die Selbstvernichtung aus (V verbraucht; neu einrichten mit neuem V). Auch ohne markierte
  Einträge (Vermerk da, Liste leer) zuerst `removeDestroyedEntries()`.

### Vernichtungs-Sitzung – was sie schreibt (Speicherverhalten)

- Beim Entsperren: V überschreiben + löschen, `zustand.json` (Fehlversuche 0, `destroyed`, `rekeyPending`). Die
  Tresordatei, die Sicherungen und `lastGenuineUnlock` bleiben unverändert (Totmann nicht verlängert);
  Rollback-Stolperdraht wie sonst.
  Echtes Entsperren schreibt ebenfalls genau einmal `zustand.json` (Fehlversuche 0, `lastGenuineUnlock`), dazu
  die Ablage des Vernichtungs-Passworts (frisch gekapselt) und nach einer Vernichtungs-Sitzung einmal die Tresordatei
  (Rotation, v4.4).
- In der Sitzung: vernichtete Einträge unsichtbar (`entries`, gelöschte, Bericht, Wiederverwendung, Import-Dubletten,
  `lastModified`); Zugriffe darauf → `io("entry.notFound")`, `upsert` mit ihrer Kennung → `io("entry.stale")`.
  Speichern wie sonst (gleicher DEK und Slots), die unsichtbaren Einträge werden unverändert mitgeschrieben,
  dazu wie bei jedem Speichern die Ablage des Vernichtungs-Passworts. `destroyedEntries`, `destructibleEntries` leer,
  `UnlockedVault.destructionStatus` ohne Vermerk.
- **Ehrliche Grenze:** Alles, was das Master-Passwort verlangt (`verify`, Passwortwechsel, Notfallkit, Stufe,
  Faktoren, Selbstvernichtung), behandelt das Vernichtungs-Passwort als falsch (`wrongPassword`, nach gleich langer
  Rechnung). Absicht: Sonst könnte die Vernichtungs-Sitzung den Zugang des Besitzers ersetzen, und das nächste
  Öffnen verriete die Vernichtung. Wer das mehrfach probiert, kann Verdacht schöpfen.

### Regeln an anderen Stellen

- Stufe < 4, solange etwas eingerichtet ist → `notAllowedAtLevel`. Mit Vernichtungs-Passwort kein anderes KDF-Profil
  (Passwortwechsel mit `kdf`, Stufenwechsel mit anderem Profil) → `notAllowedAtLevel`. Neues Master-Passwort =
  Vernichtungs-Passwort → `masterPasswordReused` (ein Argon2 mehr). Vernichtungs-Passwort = Master → ebenso.
- `setProtection` auf vernichtbare Einträge: Schutz 4/5 bleibt vernichtbar (wieder an V), darunter `notAllowedAtLevel`.
- Ersetzen des Eintrags-SE-Schlüssels stört vernichtbare Einträge nicht (`sealedKinds` ohne SE für sie); Karte und
  Sicherheitsschlüssel schon. Ein anderes V nur, solange kein Eintrag markiert bleibt (`notAllowedAtLevel`).
- Konsistenz (`checkSealing` + `checkDestruction`): vernichtbar ⇔ in `destructible`, Schutz ≥ 4, Stufe ≥ 4, V im
  Inhalt, Blob-Maske = Schutz-Maske, kein `sealed`; `duressEnabled ⇔ duress`; Bereiche; eingeschaltet nur mit V und
  Stufe ≥ 4; V ≠ Eintrags-SE-Schlüssel; Ablage-Kennung ≠ V und ≠ Eintrags-SE-Schlüssel; V und Ablage-Kennung ≠
  Entsperr-SE-Schlüssel des Kopfes (`destructionKeysAvoid(header:)` in `decryptPayload` → `corruptFile`, in `persist`
  → `crypto`; Tiefenverteidigung v4.5, sonst überschriebe das Kapseln diese Schlüssel); leere Konfiguration wird nicht
  geschrieben.
- Fehlercodes neu: `io("destruction.deadmanDays")`, `io("destruction.maxFailedAttempts")`,
  `io("destruction.duressPassword")`, `io("destruction.destroyed")`, `io("destruction.write")`, `io("entry.destroyed")`,
  `io("hw.destroy")`, `corruptFile("payload.destruction")`, `corruptFile("duress.…")`, `corruptFile("destruction.state")`.

### Schnittstelle (Festlegungen zu §23.3)

- `VaultStore.destructionStatus()`, `checkDeadman(now:) throws -> Bool` wie §23.3; `destructionKeyEraser` (Zusatz).
  `DestructionStatus.destroyed` als `destroyedTrigger`/`destroyedAt`; Hilfen `remainingAttempts`,
  `shouldWarnAboutAttempts` (ab N/2), `deadlineIsNear(now:)` (≤ 25 % Restzeit).
- `UnlockedVault`: `isDuressSession`, `destroyedEntries`, `configureDestruction(…) -> PurgeReport?` (sync + async mit
  `entryFactors:`), `removeDestroyedEntries()`; Zusätze `destructionSettings`, `destructibleEntries`,
  `destructionKeyID`, `destructionStatus` (sitzungsgerecht).
- `configureDestruction`: `duressPassword` nil = bisheriges behalten; nur mit `duressEnabled` erlaubt; `vKey` nil =
  bisheriges V. Bereiche ausserhalb → `io(…)`.

### Ehrliche Grenzen (für SICHERHEIT.md)

- `zustand.json` ist nicht geheim und nicht authentisiert: Wer sie löscht oder ändert, schaltet Zähler, Totmann und
  Vernichtungs-Passwort bis zum nächsten echten Entsperren aus; sie nennt auch, dass ein Vernichtungs-Passwort
  eingerichtet ist (§23.3 verlangt die Kopie der Einstellungen). Die gleiche Form der Ablage verbirgt sie nur vor
  einem flüchtigen Blick.
- **Manipulierter Zustand als Auslöser (bewusst, v4.5 dokumentiert nach dem Fuzzing):** Gesperrt gibt es keinen
  Schlüssel, der `zustand.json` prüfen könnte. Der Kern nimmt sie darum so, wie sie ist: Frist und letzte echte
  Entsperrung, Zählerstand, Vermerk `destroyed` und die Kennung von V. Wer sie ändert, kann damit auch eine
  Vernichtung auslösen (abgelaufene Frist, Zähler an der Schwelle, ein Vermerk, dessen Löschen „wiederholt“ wird), und
  gelöscht wird die Datei, die der Zustand als V bzw. als vernichtet nennt. Das gibt niemandem mehr, als er mit
  denselben Rechten ohnehin hat: Wer im Hardware-Ordner schreiben kann, kann jede Datei dort auch direkt löschen.
  Grenzen, die der Kern trotzdem zieht (Fuzz-Befunde vernichtung-1/-2/-4/-6/-7): Ein Zustand, der den
  Entsperr-SE-Schlüssel des Kopfes nennt (als V, als vernichtet oder als Ablage), gilt nicht (`currentState`, wie ein
  fremder Zustand) – sonst hiesse Vernichten Aussperren. Fehlt die Tresordatei oder ist ihr Kopf unlesbar, gilt das
  für die Entsperr-SE-Schlüssel der eigenen Sicherungen dieses Tresors und beiseitegelegter Tresordateien
  (`backupUnlockKeyIDs`, nur Köpfe). Auch der Vermerk des Vernichtungs-Passworts liest über `currentState`. Beim
  echten Entsperren, nach jedem Speichern und beim Notfallweg löscht der Kern als „veraltete Ablage“ nie eine Datei,
  die der Tresor braucht (Entsperr-SE-Schlüssel, Eintrags-SE-Schlüssel, V, aktuelle Ablage), und nur eine Datei, die
  wirklich eine Ablage mit dieser Kennung ist (`readDuressFile`) – sonst löschte der Notfallweg (neuer Kopf ohne
  Faktoren) den alten Entsperr-SE-Schlüssel, den Eintrags-Schlüssel oder V, die ältere Sicherungen noch brauchen.
  Das echte Entsperren übernimmt einen Vermerk auf das V des Inhalts aus dem bisherigen Zustand, auch wenn
  `checkDeadman` diesen Zustand vorher nicht gelten liess (er nannte z. B. den Entsperr-SE-Schlüssel als V); V gilt
  dann als vernichtet (kein Aufdecken mehr), gelöscht wird es erst bei der nächsten Prüfung. Was bleibt: Im
  gesperrten Zustand kennt der Kern den Eintrags-SE-Schlüssel nicht (er steht nur im verschlüsselten Inhalt); nennt ein
  manipulierter Zustand ihn als V und löst aus, sind nicht vernichtbare Einträge mit Schutz ≥ 2 bis zum Notfallcode
  unlesbar – wie wenn jemand die Datei direkt löscht.
- Wer die Uhr zurückstellt, hält den Totmann-Schalter an; wer sie vorstellt, löst ihn aus.
- Time-Machine- oder sonstige Kopien von vor dem Markieren bleiben über Notfallcode/Faktoren lesbar (der Kern
  bereinigt nur die eigenen Sicherungen und den zweiten Ort).
- Mit Vernichtungs-Passwort braucht das Entsperren doppelt so viel Arbeitsspeicher (zwei Argon2 gleichzeitig).
- Vernichtet werden die Geheimteile. Titel, Benutzer, Website und die Metadaten des Berichts (§17: reuseTag,
  Stärke-Stufe) bleiben bis `removeDestroyedEntries()` im Inhalt und in den Sicherungen: Wer das Master-Passwort hat,
  kann damit Vermutungen für das alte Passwort eines vernichteten Eintrags prüfen (wie bei allen versiegelten
  Einträgen, §17). Erzeugte Passwörter sind so nicht zu erraten.
- Der Fehlversuch wird nach dem Argon2 vermerkt (§23.2: nur `wrongPassword` zählt). Wer den Prozess genau
  zwischen Ergebnis und Vermerk beendet, spart einen Versuch; die Oberfläche zeigt das Ergebnis erst danach.
- Vernichtungs-Passwort (v4.4): Offline braucht es die Faktoren (F). Die Vernichtungs-Sitzung hält aber den echten DEK;
  wer ihn dort mit Werkzeug aus dem Speicher holt, liest Kopien der Tresordatei bis zur Rotation beim nächsten echten
  Entsperren. Wer `zustand.json` vorher löscht, verhindert diese Rotation (wie alle Vermerke dort). Ablagen aus v4.3
  waren ungebunden: Kopien davon öffnen mit dem Vernichtungs-Passwort den damaligen DEK bis zum nächsten Zugangswechsel.
- Ablage mit falscher Länge bzw. kaputtem Kopf (magic, kind, Bloblänge) unter ihrem Namen: Das Kapseln ersetzt sie
  nicht mehr (vernichtung-8, damit nie ein Schlüssel überschrieben wird); das Vernichtungs-Passwort wirkt dann erst
  wieder, wenn die Datei weg ist (beim Einrichten eines neuen Vernichtungs-Passworts bekommt es eine neue Kennung).
  Atomar geschrieben entsteht das nur durch fremdes Zutun; Bitfehler im Inhalt heilen weiter.
- reuseTag (v4.4): Alte Tags versiegelter Einträge (nur NFC) erkennt der Kern nur, wenn das Master-Passwort genau so
  getippt ist (U+00A0 statt U+0020); bis zum Neu-Versiegeln vergleichen sie sich auch untereinander nur so.

### Tests (Hilfen)

`VTresor` (Stufe 4/5 mit allen Eintrags-Faktoren und einem Software-V, dessen privater Schlüssel roh in
`Hardware/<vKeyID>.siegelhw` liegt – genau die Datei, die das Vernichten löscht), `VernichtungsProvider` (V aus dieser
Datei, sonst `SchutzProvider`), `ZaehlEraser` (zählt die Schicht, kann „untätig“ sein → Rückfall des Kerns),
`TestHooks.kdfRendezvous` (belegt, dass zwei Argon2 gleichzeitig laufen), `TestHooks.Snapshot` (Testschalter auf dem
zweiten Thread). Suiten „Selbstvernichtung: Einrichten / Auslöser / Vernichtungs-Passwort / unlesbar / Zustand“.
v4.4: `VTresor.offlineDuress(…)` (Angreifer-Sicht: nur Ablage-Kopie, Tresordatei, Vernichtungs-Passwort, wahlweise
Faktoren), `KernKryptoBefundeTests.swift` (Suiten „Krypto-Befunde: …“ zu krypto-1/-2/-3, u. a. ungebundene v4.3-Ablage
und alte NFC-Tags nachgebaut).
Datei-Befunde (v4.4): `TestHooks.kdfObserver` (ruft vor jedem Argon2 mit dessen Nummer zurück, z. B. um während der
Rechnung zu sperren), `TestHooks.failPurgeBackups` (`purgeBackups` scheitert nach dem Schreiben),
`KernDateiBefundeTests.swift` (Suiten „Datei-Befunde: …“ zu datei-1 bis datei-5).
Fuzz-Befunde (v4.5): `KernVernichtungFuzzBefundeTests.swift` (Suite „Fuzz-Befunde: Selbstvernichtung“ zu vernichtung-1
bis -8 und den paarweise verschiedenen Kennungen; Platzhalter-Dateien für Entsperr- und Eintrags-SE-Schlüssel, deren
Blob im Test sonst nicht als Datei liegt; `chflags uchg` für einen nicht beschreibbaren Hardware-Ordner).
`TestHooks.afterDuressArgon` (DEBUG): ruft beim Entsperren nach erkanntem Vernichtungs-Passwort (nach beiden Argon2,
vor dem Vermerk) zurück – Wettlauf zwischen Probe und Vermerk.
Das Fuzz-Ziel `vernichtung` (Sources/SiegelFuzz/FUZZ-NOTIZEN.md) rechnet die Abläufe dieses Abschnitts mit einem
eigenen Modell nach; wer hier etwas ändert, zieht das Modell (`ZielVernichtung.Welt`) nach.

### Datei-Befunde (v4.4)

- Nach `lock()` schreibt kein Vorgang mehr (`requireUnlocked()` unmittelbar vor jedem `persist` unter `writeLock`).
  `save`/`rekeyAndSave` liefern die geschriebene Generation; `configureDestruction` wirft nach dem Schreiben nicht mehr
  (`purgeBackups`-Fehler → `PurgeReport.interrupted`). `destructionKeyIsUnused(_:vaultID:generation:)` sagt der
  Oberfläche, ob ein neues V nach einem Fehler weg darf (Zustand nennt es nicht, Datei unverändert).
- Notfallweg für eine gewählte Datei: `recoverBackup(from:code:…)`/`(from:shares:…)`, `checkRecoveryCode(_:againstFile:)`,
  `checkRecoveryShares(_:againstFile:)`; über `install(…recoveryReset: true, reason: .recovery)`, die bisherige Datei
  wird „vor-notfall“ angeheftet. `backupInfo(fileAt:)`, `backupsDirectory`, `inspectHeaderUnverified()` (nur Kopf, nur
  für die Wahl Code/Teile).

### Ablauf-Befunde (v4.4)

- Freigaben nach dem Sperren (ablaeufe-4): `LockCheckedEntryFactors` (UnlockedVault+Schutz.swift) umhüllt den
  Provider beim Aufdecken (`revealSecrets`, `revealDestructible`) und in `releaseGroups` (dort zusätzlich eine Prüfung
  vor der ersten Gruppe): gesperrt → `io("vault.locked")`, ohne den Provider zu rufen. Tests in `KernSchutzTests`
  („Befund ablaeufe-4: …“, mit `SchutzProvider.onAnswer` bzw. `TestHooks.kdfObserver`).
- `DestructionStatus.keyConfigured` (ablaeufe-5): `vKeyID != nil || destroyed != nil` aus `zustand.json`; offen
  zusätzlich `destructionKeyID != nil`. Test „Befund ablaeufe-5: …“ in `KernVernichtungTests`.
