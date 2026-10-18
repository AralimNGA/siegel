# SiegelUI – Notizen (Stufe 1 + 2, Härtestufe v4 Stufe A + B, Selbstvernichtung v4.3)

Stand 17.10.2026. Bindend bleibt `SPEC.md` (jetzt v4, §13–§22). Stufe 1 hat Grundgerüst, Abläufe ausserhalb des
Tresors und die Plattform-Härtung gebaut, Stufe 2 die Tresor-Hauptansicht und die Datei-Abläufe, **v4 Stufe A** die
Oberfläche der Härtestufe (Faktoren, Sicherheitsstufen, Notfallcode in Teilen, Schutz pro Eintrag), **v4 Stufe B**
2FA-Codes, Sicherheitsbericht, KeePass-Export, Autofill-Stand, Lizenzen und die Review-Befunde #19–#48 der
Oberfläche (Abschnitt „Härtestufe v4 – Stufe B“ unten). **v4.3** (17.10.2026): Selbstvernichtung nach SPEC §23
(Abschnitt „Selbstvernichtung (v4.3)“ unten), gebaut gegen eine Attrappe der §23.3-Kern-API.

## Architektur in einem Satz

`SiegelApp` (eine `Window`-Szene) → `AppDelegate` (Härtung, Beenden, Einzelinstanz) → `AppModel`
(`@MainActor @Observable`, Zustandsmaschine) → `RootView` wählt den Bildschirm nach `model.screen`.
Alle Formularzustände liegen als kleine `@Observable`-Klassen im Modell (nicht in `@State`), damit
Sperren sie gezielt verwerfen und Snapshots sie füllen können.

## Dateien

| Ordner/Datei | Inhalt |
|---|---|
| `SiegelApp.swift` | `public struct SiegelApp: App`, `AppDelegate`, `MenuScrubber`, `SiegelCommands` (⌘N ⌘F ⌘E ⌘L ⌘,) |
| `Modell/AppModel.swift` | Zustandsmaschine, Tresor-Abbild, `perform`, Sperren, Beenden, zweiter Sicherungsort, SPI für Snapshots; Stufe 2: `browser`, `flowState`, `exportedCSV`, `listCache` (beim Sperren neu) |
| `Modell/AppModel+Ablaeufe.swift` | Einrichtung, Entsperren (die 2-s-Wiederholung macht der Kern), Notfallcode-Weg, Notfallkit, Tresor fehlt, Beschädigt, Rollback |
| `Modell/AppModel+Einstellungen.swift` | Einstellungen-Seite: KDF-Profil, Passwortwechsel, Code prüfen, neues Kit, Sicherungsort; `request(_:)` legt `FlowState` an |
| `Modell/Zustaende.swift` | Zustände der Stufe-1-Bildschirme, `PendingFlow`, `VaultCommand`, `Notice`, `PasswordAssessment` |
| `Modell/AppSettings.swift` | Einstellungen in `UserDefaults` (nur Einstellungen, nie Inhalte) |
| `Modell/Fehlertexte.swift` | `SiegelError` → deutsche Meldungen (Codes werden nie angezeigt); v4: `factorMissing`, `factorUnavailable` (je Faktor), `factorCancelled`, `wrongCard`, `notAllowedAtLevel`, `totpInvalid`, `wrongPasswordOrFactor`; v4.4: `factorTemporarilyUnavailable` (`se.lockout`, `se.notReachable`, `fido.busy`), `wrongSecurityKey` |
| `Haertung/…` | WindowGuard, SecretPasteboard, AutoLock, SingleInstance, ExternalDisplayGuard/`SecretGate`, FileVault, Secure Event Input, Prozess-Härtung, Aufräumen |
| `Felder/` | `HardenedTextField`, `SecretField`, `SecretTextView`, `MasterPasswordField`, `RecoveryCodeField`, `TextHardening` (Stufe 2: `complete(_:)` abgeschaltet – keine Vervollständigungsliste mit Wörtern aus Geheimnissen) |
| `Theme/` | Farben exakt §7, Schriften, Masse, Knopfstile, Bausteine, `SiegelMark` |
| `Bildschirme/` | `RootView`, `SetupView`, `RecoveryKitView`, `LockView`, `RecoveryFlowView`, `StatusViews`, `SettingsView` |
| `Drucken/RecoveryKitPrinter.swift` | Druckerprüfung, Blatt als NSView, ohne Vorschau, Auftrag „Dokument“; v4: `PrintSheetContent` für Teile („Teil x von 3“) und die Schlüsselkarte |
| **`Tresor/` (Stufe 2)** | |
| `Tresor/TresorZustand.swift` | `VaultBrowserState` (Modus browse/edit/trash, Auswahl, Aufdecken, Verlauf), `EntryEditorState` (Entwurf + Generator), `EntryRules` (Feldgrenzen §3, Titel-Ersatz, „Entwurf <Datum>“), `FlowState` + `ImportPreview` |
| `Tresor/AppModel+Tresor.swift` | Liste (Sortierung, Suche nur Titel/Benutzer/URL), Auswahl/Pfeile, Detail-Aktionen, Löschen/„Zuletzt gelöscht“, Bearbeiten/Sichern/Abbrechen, Generator, Lock-Hook |
| `Tresor/AppModel+Dateien.swift` | CSV-Import, CSV-Export, Sicherung exportieren/einspielen (Panels geschützt, Abschluss-Handler prüfen Sperre) |
| `Tresor/Website.swift` | `Website.parse` (nur http/https öffnen, ohne Schema → https), `Punycode` (RFC 3492), `ScriptCheck` (gemischte Schriften) |
| `Tresor/VaultView.swift` | Seitenleiste (Kopf mit Logo 21 pt, + ⚙︎ Schloss; Suche; Liste als ScrollView/LazyVStack; Fusszeilen) und Detail-Weiche |
| `Tresor/EntryDetailView.swift` | Detail, `DetailRow`, `DetailHeader`, `InlineConfirm`, `ReuseWarning`, `TresorMetrics`, `WindowDragArea` |
| `Tresor/EntryEditView.swift` | Bearbeiten/Neu mit eingebautem `GeneratorPanel` |
| `Tresor/TrashView.swift` | „Zuletzt gelöscht“, leerer Tresor, nichts gewählt |
| `Tresor/FlowView.swift` | Seiten der Abläufe (CSV, Sicherungen) |
| `Tresor/StatusZeilen.swift` | `VaultStatusLines`: Notfallkit-Zeile (nicht wegklickbar), „Exportdatei endgültig löschen“, „Keine Sicherung ausserhalb dieses Macs“ |
| `Tresor/TresorBausteine.swift` | `SecretLabel` (Geheimnis-Anzeige auf `SecretNSTextField`), `SecretNotesView` (`SecretTextViewCore`, nicht auswählbar), `PasswordValue`, `IconButton`, `CompactButtonStyle`, `MonoCheckbox`, `MonoSlider`, Suchfeld |

## Tresor-Ansicht (Stufe 2) – wie sie arbeitet

- **Auswahl/Modus** liegen in `model.browser` (`VaultBrowserState`). `model.select(id)`, `moveSelection(by:)`,
  `editSelected()`, `newEntry()`, `showTrash()`. `syncVaultCommands()` hält `canEditEntry` (⌘E) aktuell.
- **Menübefehle**: `installVaultHooks()` (aus `VaultView.onAppear`) setzt `commandHandler` (⌘N, ⌘F, ⌘E) und den
  Lock-Hook `"tresor.bearbeiten"`.
- **Liste**: `model.visibleEntries` (sortiert, gefiltert; Zwischenspeicher nach `revision` + Suchtext).
  Tastatur: Pfeile, Enter = Bearbeiten, Esc leert die Suche; im Suchfeld führen ↓ und Enter in die Liste.
  Auswahl schwarz mit weisser Schrift; beim Bearbeiten wird die Liste grau und ist gesperrt.
- **Detail**: Passwort verdeckt (feste 10 Punkte, verrät die Länge nicht); aufgedeckt über `SecretGate` +
  `SecretLabel` (zeichnet nur in geschützten Fenstern, auf externen Bildschirmen „Hier zeigen“). Notizen über
  `SecretNotesView`, nicht auswählbar. Kopieren nur über `model.copySecret` (⇧⌘C = Passwort).
  Website: Anzeige ohne Schema, gemischte Schriften als Punycode mit Hinweiszeile, Öffnen nur http/https.
  „Frühere Passwörter (n)“ aufklappbar, je Zeile Datum, verdeckt/Auge, kopieren; „Verlauf leeren…“ mit
  Bestätigung in der Zeile (keine NSAlerts – die zeigen die Systemakzentfarbe).
- **Bearbeiten** (§7.5, §6 b): `saveEdit()` prüft Feldgrenzen und Titel (leer → Host der Website, sonst Meldung).
  `applyGenerated()` speichert sofort **nur das Passwort** auf den gespeicherten Stand (neuer Eintrag: wird mit
  dem Formularstand angelegt, Titel notfalls „Entwurf <Datum>“). `cancelEdit()` nach „Übernehmen“: altes
  Passwort per `upsert` zurück (das generierte landet so im Verlauf); ein erst durch „Übernehmen“ angelegter
  Eintrag wandert nach „Zuletzt gelöscht“ – das übernommene Passwort geht nie verloren.
- **Sperren ohne Datenverlust** (§6 a): `saveDraftBeforeLock` läuft synchron vor dem Verwerfen; geänderter
  Entwurf → `upsert`, ohne Titel/Website als „Entwurf <Datum>“, bei verletzten Grenzen gekürzt (letzter Ausweg).
  Geschützte, vernichtbare und vernichtete Einträge nur über `writeSealedDraft` (v4.4, hygiene-1): Schutz aus
  `draftProtection` (gewählt, sonst höchster eingerichteter ≥ bisherigem), Metadaten zuerst, dann `setProtection`;
  nie eine Klartext-Kopie. Eigener „Entwurf <Datum>“ nur bei Schutz 1 vorher und nachher (`writeOpenDraft`, mit 2FA).
  Abweichungen meldet `LockParticipantResult.doneWithNotice` bzw. `lost(_, notice:)` als `lockNotice`.
- **Löschen** → `delete(id:)` und nächster Eintrag gewählt. „Zuletzt gelöscht (n)“ erscheint unten, sobald n > 0.
- **Rückmeldungen** erscheinen in der Tresor-Ansicht mittig über dem Detailbereich (RootView rückt ein).
- **Kopfzeilen** 36 pt hoch, Mitte knapp unter den Fensterknöpfen; leere Kopfflächen ziehen das Fenster
  (`WindowDragGesture`). Geprüft: Klicks im Titelleistenbereich erreichen den SwiftUI-Inhalt.

## Abläufe (Stufe 2)

`model.request(.csvImport | .csvExport | .backupExport | .backupImport)` legt `flowState` an; `RootView` zeigt
dann `FlowView`. `finishFlow()` führt zurück (in die Einstellungen oder den Tresor, je nachdem woher).

- **CSV-Import**: Panel → Datei ≤ 16 MiB im Hintergrund lesen → `CSVImport.parse` → `csvImportShowPreview`
  (Format, Anzahl, Spalten-Zuordnung, Dubletten/Konflikte wie `importEntries` geschätzt, 2FA-/Notizen-/
  Steuerzeichen-/Apostroph-Hinweise, erste 5 Titel) → `importEntries` → Bericht → „Quelldatei jetzt endgültig
  löschen?“ (`FileManager.removeItem`, nicht Papierkorb). Die geparsten Einträge werden nach dem Import verworfen.
- **CSV-Export**: Warnung → Ordner-Panel → bei unverschlüsseltem oder unbekanntem Volume zweite Bestätigung →
  Master-Passwort → `exportCSV(toParent:masterPassword:)` (Kern prüft Passwort und iCloud) → Fertig-Seite;
  `model.exportedCSV` hält die Zeile „Exportdatei endgültig löschen“ (Datei + leerer `.noindex`-Ordner) bis
  erledigt oder weggeklickt (auch über das Sperren hinweg, nicht gespeichert).
- **Sicherung exportieren**: NSSavePanel → `store.exportBackup(to:)`; liegt das Ziel auf einem anderen Volume
  oder in iCloud Drive, ruft die App `noteExternalBackup()` auf (die Zeile „Keine Sicherung ausserhalb…“
  verschwindet für 30 Tage).
- **Sicherung einspielen**: Panel → Master-Passwort der Sicherung → `store.importBackup` (Argon2, `heavy`) →
  alter Tresor `lock()`, Ansicht neu, `open(neu)`. Offene Bearbeitung wird vorher in den alten Tresor gesichert.

## Snapshots

`swift run SiegelSnapshots snapshots` rendert 176 Bilder (Stufe 1/2: 72, Härtestufe A: 80–118 inkl. 113b, B: 119–138,
v4.3: 139–158 mit b-Bildern) (920×600 @2x, einzelne grösser/kleiner; `SIEGEL_SNAPSHOTS_NUR=B` rendert nur Stufe B,
ca. 45 s, `SIEGEL_SNAPSHOTS_NUR=V43` nur die Selbstvernichtung, ca. 65 s) und prüft dabei
die Abläufe (Exit-Code 1 bei Fehlern). Stufe 2: `Sources/SiegelSnapshots/Tresor.swift` (Bilder 41–71 plus
Logik-Prüfungen: Punycode-Testvektoren, gemischte Schriften, Schemata, Suche, Sortierung, Pfeile, Übernehmen/
Abbrechen, Sichern, Titel aus Website, Neu+Übernehmen+Abbrechen, Papierkorb, Verlauf leeren, Sperren speichert
Entwurf, CSV-Import/-Export mit echten Temp-Dateien, Sicherung exportieren/einspielen). Grau angedeutete
Fensterknöpfe oben links (`Fensterknoepfe`) zeigen nur, wo im echten Fenster die Ampel sitzt. Rückmeldungen
früherer Schritte werden vor jedem Bild entfernt (`keepNotice: true` behält sie). Die Zwischenablage wird in
Snapshots nie berührt.

Wichtig beim Rendern: Nach dem ersten `await` läuft der Top-Level-Code als Job auf der Main-Queue;
`DispatchQueue.main.async` und `Task { @MainActor }` laufen dann während `RunLoop.run` nicht. Darum nutzt
`WindowProbe` `RunLoop.main.perform`. App Nap ist im Snapshot-Programm abgeschaltet.

## Abgleich mit dem echten Kern (Integration 16.10.2026)

- Bestätigt: `restoreNewestReadableBackup` sichert eine beschädigte Datei selbst nach `Sicherungen/beschaedigt-…`
  (clonefile, dann atomar ersetzt); die UI ruft `quarantineCorruptVault` nicht auf.
- Bestätigt: `upsert` legt das alte Passwort in den Verlauf und nimmt das aktuelle heraus („Abbrechen nach
  Übernehmen“); `upsert` läuft synchron auf dem Main-Thread (Lock-Hook). `importEntries` vergleicht nur mit nicht
  gelöschten Einträgen. `exportBackup(to:)` ersetzt eine vom Panel bestätigte Datei atomar.
- Bestätigt: Gruppen gross/klein, mit oder ohne Bindestrich; `commitRecovery` mit dem Kit aus `create` setzt nur
  `recoveryConfirmedAt`.
- Angepasst: `unlock` wartet bei `corruptFile`/`kdfParametersOutOfRange`/`unsupportedVersion` selbst 2 s und liest
  einmal neu – die UI wiederholt nicht mehr zusätzlich.
- Angepasst: Bei `unsupportedVersion` gibt es keinen Knopf „Neueste lesbare Sicherung öffnen“ mehr. Der Kern
  überschreibt eine Datei mit höherer Version nie, auch nicht beim Wiederherstellen (SPEC §2).
- Angepasst: KDF-Profilwechsel mit gleichem Passwort wird im Kern nicht mehr durch `masterPasswordReused`
  blockiert (das unveränderte Passwort ist kein *neues*).
- Angepasst: „Passwort = Wiederholung“ über `VaultStore.passwordsMatch` (gleiche RFC-8265-Abbildung wie der Kern).
- Angepasst: deutsche Meldungen für die 14 reason-Codes von `CSVImport.parse` und die festen `.io`-Codes des Kerns
  (`Fehlertexte.csv`/`Fehlertexte.io`).
- Notfallcode-Korrektur (SPEC §1.5): Mit `?` probiert der Kern nur die Belegungen der `?`, ohne `?` 1–2 Ersetzungen
  und vertauschte Nachbarn – nicht beides zusammen.
- Snapshots laufen mit dem echten Kern (1 GiB Argon2) und lesen den CSV-Import über den echten `CSVImport.parse`.

## Härtestufe v4 (Stufe A, 17.10.2026)

Gebaut gegen die §22-Schnittstelle. In der Kopie der Oberfläche steckte der v3.1-Kern; die v4-Methoden lieferte eine
**Attrappe** (`Sources/SiegelCore/Attrappe/AttrappeV4.swift`, wird bei der Integration verworfen). Die Oberfläche
ruft nur §8/§22 auf. Die Attrappe merkt sich Stufe/Faktoren in `<Ordner>/Attrappe-v4/<vaultID>.json` (Kennungen und
Prüfwerte), versiegelte Geheimteile nur im Speicher, und ihr Shamir 2 aus 3 ist echt (GF(2^8)).

### Neue Dateien

| Datei | Inhalt |
|---|---|
| `Modell/FactorHardware.swift` | Protokoll `FactorHardware` (+ `CardScanning`, `SecurityKeyChoice`), `SystemFactorHardware` = genau die §22-Aufrufe von SiegelHardware; `FactorUI` (Namen „Touch ID / Karte / Schlüssel“, Symbole `touchid`, `qrcode`, `key.horizontal`, Passwort `ellipsis.rectangle`). Snapshots setzen per `snapshotUseHardware` eine Attrappe ein – nie echte Touch-ID-Dialoge oder Kamera in Snapshots. |
| `Modell/FaktorZustaende.swift` | `FactorCollection` (Faktoren eines Kopfs einsammeln, Status je Faktor, `FactorFailure`), `CardScanState`, `KeyTouchState`, `SecurityWizardState` (Assistent, Schritte `intro/verify/touchID/card/securityKey/recovery/apply/done`). Geheimnisse nur in `@ObservationIgnored`-Feldern, `wipe()`/`reset()` verwerfen sie. |
| `Modell/AppModel+Faktoren.swift` | Touch ID (`factorOperation` im Hintergrund), Kamera-Sheet (`scanCard` mit Continuation; Karten-Kennung `CardCode.tag` vor dem Rechnen geprüft, falsche Karte → Hinweis im Sheet, Scanner startet neu), Schlüssel-Sheet (`touchSecurityKey`, Geräteliste jede Sekunde, genau einer → sofort „berühren“), `collect(_:)` der Reihe nach Touch ID → Karte → Schlüssel, `factorsForFile`/`vaultFactors`, Stufenregel `passTouchIDGate`, `UIEntryFactorProvider` (§22 `EntryFactorProvider`). |
| `Modell/AppModel+Stufe.swift` | Assistent: `startLevelChange`, `startEnroll(_:fromEditor:)`, `wizardVerify` (`verify(masterPassword:factors:)`), `wizardSetupTouchID` (Entsperr- + Eintrags-SE-Schlüssel), Karte erzeugen/drucken/abschreiben/scannen, `wizardRegisterKey`, `wizardShowRecoveryKit` (Kit in neuer Form über den Notfallkit-Bildschirm, Herkunft `.levelChange`), `wizardApply` (`changeSecurityLevel` bzw. `enrollFactors`), Abschluss mit Frage nach alten Sicherungen; abwärts wird der alte SE-Entsperr-Schlüssel erst **nach** dem Schreiben entfernt; abgebrochene Assistenten entfernen angelegte SE-Schlüssel wieder. |
| `Tresor/AppModel+Schutz.swift` | Schutz pro Eintrag: `needsReveal` (Schutz ≥ 2 oder Stufe 3+), `visibleSecrets`, `obtainSecrets` (Provider bzw. Touch-ID-Regel), `revealEntry`/`hideEntrySecrets`, `copyEntrySecret(_:_:)` (Passwort, Notizen, 2FA-Code, Verlauf), `unlockEditorSecrets`, `writeSealed` (Metadaten per `upsert`, Geheimteile per `setProtection`), `enrollForEditor`. |
| `Bildschirme/FaktorAnsichten.swift` | `FactorPill`/`FactorProgressView`/`CollectionProgress` (Kapseln Passwort → Faktoren, Aufforderung bzw. Fehler mit „Erneut versuchen“ und – bei `factorUnavailable`/`wrongSecurityKey` – „Notfallcode verwenden“; bei `FactorFailure.temporary` ist „Erneut versuchen“ der Hauptknopf, ohne Notfallweg), `FactorSheetHost` + `SheetBackdrop`, `CardScanSheet` (Vorschau-Ebene aus `QRScanner.previewLayer`, ohne Kamera Platzhalter; Abtippen), `SecurityKeySheet`, `KeyGlyph`, `TouchIDGlyph`. |
| `Bildschirme/SicherheitsstufeView.swift` | `SecurityLevelOverview` (Tabelle §13: Stufe / Zum Öffnen / Im Notfall, Detail „Was du zum Öffnen brauchst / was im Notfall / Regeln“), `SecurityWizardView`, `KeyCardPreview`, `LevelBadge`, `FactorGlyphs`, `StepDots`, `LevelTexts`. |
| `Tresor/SchutzAnsichten.swift` | `ProtectionPicker` (1–5 mit Erklärung und Faktor-Symbolen, „noch einrichten“), `ProtectionSegments` (Vorgabe in den Einstellungen, unter dem Stufen-Minimum gesperrt), `ProtectionGlyphs` (Liste/Detail), `TOTPValue` (2FA-Code mit Restsekunden). |
| `SiegelSnapshots/Haertestufe.swift` | `DemoHardware` (Schranken für „Touch ID wartet“/„Schlüssel berühren“, Kamera-Status, Geräteliste), `DemoScanner` (`deliver(payload)`), Bilder 80–118 + Prüfungen. |

### Wie die Abläufe gehen

- **Entsperren** (`submitUnlock`): Kopf per `inspect()` (schon beim Erscheinen des Sperrbildschirms, `loadLockHeader`),
  dann Passwort → Touch ID → Karte → Schlüssel → `unlock(masterPassword:factors:)`. Erledigte Faktoren bleiben nach
  einem Abbruch stehen („Erneut versuchen“/Enter macht beim offenen Faktor weiter); nach **jedem** Entsperr-Versuch
  werden alle verworfen. Falsch → „Passwort oder ein Faktor stimmt nicht“ (§13.1). `factorUnavailable` → Notfallweg
  (Hauptknopf), daneben „Erneut versuchen“ als Knopf mit Rahmen (v4.4, bau-1). Touch ID gesperrt/nicht erreichbar (`factorTemporarilyUnavailable`, v4.4) → nur „Erneut versuchen“ (Hauptknopf),
  der leise „Notfallcode verwenden“ unten bleibt. Schlüssel-Sheet: jeder Versuch hat ein `SecurityKeyCancellation`
  in `KeyTouchState`; „Abbrechen“ und Sperren setzen es (Vorgang endet sofort). Kamera-Sheet: „Abtippen“ stoppt
  den Scanner, „Kamera verwenden“ startet ihn wieder.
  Die Faktor-Zeile hat eine feste Höhe (das Logo springt nicht).
- **Notfallweg**: `inspect()` sagt ein Code oder zwei Teile. Teile: `checkRecoveryShares` → Korrekturen je Teil
  bestätigen → `recover(shares:)`. Danach Hinweis „Stufe und Schutz aller Einträge wieder 1“, wenn der Kopf
  Faktoren oder Teile hatte.
- **Einstellungen → Sicherheitsstufe**: Übersicht, Zielstufe wählen, Assistent (Seite `.wizard` der Einstellungen).
  Das Notfallkit in neuer Form zeigt der vorhandene Notfallkit-Bildschirm (`KitState.origin == .levelChange`,
  Teile als Reiter „Teil 1 von 3“, je Teil drucken oder abschreiben, Bestätigung je Teil eine Gruppe, lokal geprüft);
  geschrieben wird erst mit `changeSecurityLevel`.
- **Regeln der Stufe** (`model.policy`): Touch ID vor jedem Aufdecken/Kopieren (Stufe 3+, auch Schutz-1-Einträge,
  auch Bearbeiten öffnen), Sperre beim App-Wechsel (`LockReason.deactivated`; während eines Faktor-Vorgangs –
  der Touch-ID-Dialog kann Siegel kurz inaktiv machen – erst danach; sie leert die Zwischenablage nicht, v4.4),
  Zwischenablage `effectiveClipboardSeconds` (Einstellung ∧ Stufe ∧ Eintrags-Schutz; für ⌘C aus Geheimnis-Feldern
  beim Kopieren über `SecretPasteboard.fieldCopyLifetimeProvider` mit `activeFieldProtection`, v4.4), Auto-Sperre `effectiveAutoLockMinutes`
  (auch im gesperrten Zustand die zuletzt bekannte Höchstdauer), CSV-Export gesperrt (Zeile in den Einstellungen,
  `request(.csvExport)` tut nichts), Profil ab Stufe 3 fest. Neue Einträge: `effectiveDefaultProtection`.
- **Schutz pro Eintrag**: Liste zeigt die Faktor-Symbole, Detail eine Leiste „Geschützt / Aufdecken“ bzw.
  „Aufgedeckt / Verbergen“. Aufgedeckte Teile liegen in `browser.unlockedSecrets` (fallen bei Auswahlwechsel,
  Verbergen, Sperren weg). Kopieren ohne Aufdecken holt die Teile nur für dieses Kopieren. Bearbeiten: Titel,
  Benutzer, Website ohne Faktoren; Passwort/2FA/Notizen erst nach „Aufdecken“; Schutz ändern nur aufgedeckt;
  fehlt ein Faktor → „Jetzt einrichten…“ (Assistent `.enroll`, danach zurück zum Entwurf).
- **Sichern geschützter Einträge** (`writeSealed`): neuer Eintrag zuerst **ohne** Geheimteile per `upsert`, dann
  `setProtection` – so wird nie Klartext eines geschützten Eintrags geschrieben. Bestehende: Metadaten per `upsert`
  des gespeicherten (versiegelten) Eintrags, Geheimteile per `setProtection`. Den Verlauf versiegelter Einträge pflegt
  die Oberfläche (`EntryRules.history(after:newPassword:)`), weil der Kern das alte Passwort ohne Faktoren nicht kennt.
- **Wiederherstellen/Einspielen** (Tresor fehlt, Beschädigt, Sicherung einspielen): Faktoren nach dem Kopf der Datei
  (`inspect(fileAt:)`; bei „Beschädigt“ der neuesten lesbaren Sicherung).
- **Drucken**: `PrintSheetContent` (.recovery, .share, .card) – gleiche Regeln wie das Notfallkit (nur Papier,
  Druckerprüfung, „Dokument“). Die Karte wird in Originalgrösse mit Schnittlinie gedruckt.

### Integration (Stufe B)

1. `Sources/SiegelCore/Attrappe/` löschen, echten Kern + SiegelHardware einsetzen, `swift build`.
2. Annahmen prüfen (stehen auch unter spec_issues der Übergabe):
   - `upsert` eines Eintrags mit `secretsSealed == true` ändert nur Metadaten und behält die versiegelten Teile.
   - `setProtection(_:id:secrets:)` übernimmt `secrets.history` wie übergeben.
   - `commitRecovery` nimmt bei `.shamir2of3` drei Gruppen (die Attrappe konnte das nicht; „Neues Notfallkit…“ in
     Stufe 4/5 ist darum in den Snapshots nur bis zur Bestätigung gezeigt).
   - `changeSecurityLevel`: Faktoren, die beide Stufen haben, kommen aus `currentFactors`; eine schon für Einträge
     eingerichtete Karte wird als `newFactors.card` (dasselbe q) übergeben.
   - Teile: 56 Zeichen in 12 Gruppen (`RecoveryFlowView.shareCharacters`), Kartencode 55 Zeichen (11 Gruppen).
3. Snapshots mit echtem Kern laufen lassen (`swift run SiegelSnapshots`), Bilder 80–118 ansehen; die Hardware bleibt
   in Snapshots die Attrappe (`DemoHardware`).
4. Manuell (PRUEFLISTE): echter Touch-ID-Dialog (Sperre beim App-Wechsel darf dabei nicht auslösen), Kamera-Vorschau
   und Erkennung mit gedruckter Karte, Kamera verweigert → Abtippen, Sicherheitsschlüssel (mit Gerät), Druck der Karte
   (Grösse 85,6 × 54 mm, QR mit Handy-Kamera **nicht** testen – Live Text), Sheets in Bildschirmaufnahmen unsichtbar.

### Offen aus Stufe A (Stand nach Stufe B)

- Erledigt in Stufe B: KeePass-Export, Sicherheitsbericht, Autofill-Erklärung, 2FA-Anzeige (siehe unten).
- CSV-Export ab Stufe 2 sammelt die Faktoren ein (Weg vorhanden, ohne eigenes Bild).
- Für `.shamir2of3` fehlt in §22 ein Weg über die Sicherungen (`recoverFromNewestReadableBackup(shares:)`); bei
  beschädigter Datei zeigt der Teile-Weg einen Hinweis auf „Tresor fehlt“/Master-Passwort. Mit Befund #29 gibt es
  dort jetzt auch „Sicherung aus Datei einspielen…“ (mit Master-Passwort).

## Härtestufe v4 – Stufe B (17.10.2026)

### Neue Dateien

| Datei | Inhalt |
|---|---|
| `Modell/TOTPAnzeige.swift` | `TOTPReading` (Code, Restsekunden, Periode, „123 456“), `TOTPCheck`, Protokoll `TOTPSource`, `CoreTOTPSource` (nur `TOTP.parse` + `TOTP.code`; die Periode kommt aus dem Code zum Zeitpunkt 0, weil die Felder von `Parameters` in §22 offen sind), `TOTPDisplay` (Zugriff der Oberfläche; SPI `snapshotUse`). |
| `Tresor/Sicherheitsbericht.swift` | `SecurityReportSummary` (nur bestehende Einträge, Reihenfolge gleich wie Master → wiederverwendet → schwach → alt), `scheduleSecurityReport`/`updateSecurityReport` (Hintergrund, nach jedem `refreshSnapshot`), `showSecurityReport`/`openReportEntry`, Ansichten `SecurityReportView`, `ReportTile`, `ReportEntryRow`, `ReportLine` (Seitenleiste), `ReportFindingsLine` (Detail). |
| `Tresor/AppModel+KeePass.swift` | KeePass-Ablauf (§19): Ordner, Master-Passwort + Faktoren, Export-Passwort nach `MasterPasswordPolicy` (nicht gleich dem Master-Passwort), `exportKeePass`, Exportdatei löschen. |
| `Bildschirme/InfoAnsichten.swift` | `AutofillPage` (§20: Stand, Regeln, Einrichten mit bezahltem Konto), `LicensesPage` + `LicenseTexts` (Befund #44: libsodium ISC, zxcvbn MIT, web2 gemeinfrei, Apple-Frameworks; Lizenztexte unverändert aus LIZENZEN.md), Version. |
| `SiegelSnapshots/StufeB.swift` | `DemoTOTP` (RFC 6238/4648, nur solange der Kern-Platzhalter nichts rechnet – danach prüfen die Snapshots automatisch den Kern), Bilder 119–138, Prüfungen zu allen Befunden. |

### Abläufe

- **2FA (§18)**: Bearbeiten – Feld „2FA-Geheimnis“ (SecretField), darunter die Prüfung über `TOTP.parse` (leer: Hinweis,
  gültig: „6 Ziffern, neuer Code alle 30 s“ + Hinweis auf den zweiten Faktor im selben Tresor, ungültig: Meldung);
  Sichern lehnt ungültige Geheimnisse ab und schneidet Rand-Leerzeichen ab (beim Sperren wird trotzdem gespeichert).
  Detail – Zeile „2FA-Code“ mit Code in SF Mono 17 (SecretLabel, nur in geschützten Fenstern), Ring und Restsekunden
  (letzte 5 s fett), Kopieren über `copyEntrySecret(.totpCode)` → SecretPasteboard. Schutz ≥ 2 bzw. Stufe 3+: erst
  nach dem Aufdecken; bei offenen Einträgen in Stufe 3+ steht „Verborgen“ (Kopieren holt Touch ID).
  CSV-Import-Texte: OTPAuth/login_totp landen im 2FA-Feld (§18), nicht mehr „in Notizen“.
- **Sicherheitsbericht (§17)**: Seitenleiste „Sicherheit“ (Zahl betroffener Einträge) über „Zuletzt gelöscht“,
  `browser.mode == .report`. Vier Zähler, je Kategorie eine Liste (wiederverwendet in Gruppen), Klick springt zum
  Eintrag. Im Detail eine Zeile mit den Befunden des Eintrags (Klick öffnet den Bericht). Der Bericht hält nur UUIDs.
- **KeePass (§19)**: Einstellungen → Import und Export → „KeePass exportieren (verschlüsselt)…“ (Stufe 4/5 gesperrt,
  Zeile mit Schloss). Einführung (was exportiert wird, was nicht: frühere Passwörter, „Zuletzt gelöscht“, Schutz 4/5)
  → Ordner → Master-Passwort, Export-Passwort ×2 mit Stärke-Anzeige → Faktoren → Fertig (Datei löschen, im Finder).
  Kein Schritt „unverschlüsseltes Volume“: die Datei ist verschlüsselt.
- **Autofill (§20)**: Abschnitt „Automatisches Ausfüllen“ mit „Vorbereitet, nicht aktiv“ → Seite mit Stand, Regeln und
  Einrichten (`SIEGEL_TEAM_ID=… skripte/autofill_bauen.sh`, Skript kommt vom Autofill-Agenten).
- **Info**: Version (aus dem Bündel, sonst „Entwicklung“) und „Lizenzen…“.

### Review-Befunde (Runde 1) – was die Oberfläche jetzt tut

- #19 Fremder Code: Meldung nennt nur die Kit-Kennung dieses Tresors (`Fehlertexte.wrongKit`), auch bei Teilen.
- #21 Notfallweg behält das Profil: `recover…(kdf: recovery.kdfToKeep)` (Stark nur, wenn der Kopf Stark sagt; sonst
  Standard). `kdfFailed` bei Stark → „Mit Profil Standard wiederherstellen“ statt still herabzustufen.
- #24 Die Eingabe, die die Auto-Sperre auslöst, wird verschluckt; `copySecret` nur entsperrt; `lock()` leert die
  Rückmeldezeile.
- #25/#35 `kitFinish` prüft nach dem Entfernen Epoche, Tresor, Bildschirm und Kit; `go(.unlocked)` ohne Tresor führt
  immer zu `route()` (Sicherheitsnetz).
- #26 Beenden mit liegender CSV-Exportdatei: Systemfrage „Löschen und beenden / Behalten und beenden / Abbrechen“
  (ohne Standardknopf, Esc = Abbrechen). Fertig-Seite sagt ehrlich, wie lange die Zeile erinnert.
- #27/#31 Sperren mit nicht speicherbarer Bearbeitung: ⌘L wird abgelehnt (Fehler im Formular, Hinweiszeile); ein zweites
  ⌘L innerhalb von 20 s sperrt trotzdem. Auto-Sperre/Ruhezustand sperren immer; dann steht auf dem Sperrbildschirm
  „… liess sich vor dem Sperren nicht speichern (Grund) und ist verloren“, nach dem Entsperren nochmals als Rückmeldung.
  Fehler, die nicht am Eintrag hängen (Platz, fremde Änderung), werden nicht ein zweites Mal versucht.
- #28/#33 „Trotzdem öffnen“ merkt (vaultID, Generation, SHA-256 der Datei) in `AppSettings.acceptedRollback`: genau
  diese Datei öffnet danach ohne Frage, jede andere ältere warnt weiter; beim ersten normalen Entsperren danach gelöscht.
- #29 „Tresordatei beschädigt“: „Sicherung aus Datei einspielen…“ (Panel → `importBackup` mit Faktoren nach dem Kopf),
  „Tresor im Finder zeigen“, zweiter Sicherungsort wird vorher neu aufgelöst, Meldung weist auf den Datei-Weg.
- #30 Auto-Sperre merkt die letzte Eingabe und liest die Minuten erst beim Prüfen.
- #32 Eingefügtes Master-Passwort wird auch nach Einrichten, Passwortwechsel, Profil, neuem Kit, CSV-/KeePass-Export,
  Assistent, „Ältere Sicherungen entfernen“ und beim Sperren geleert (nur wenn die Zwischenablage unverändert ist).
- #34 Frage „Alte Sicherungen entfernen?“ ohne andere Ausgänge (kein Zurück/Fertig/Esc) und in
  `AppSettings.pendingPurgeQuestion` gemerkt (vaultID + Anlass) bis zur Antwort – auch über Sperren und Neustart.
  Anlässe: Passwortwechsel, neues Kit, Stufenwechsel (eigener Text).
- #36 ⌘, Einstellungen und alle Abläufe sind während einer Bearbeitung gesperrt.
- #37 Sicherheitstext nennt den zweiten Sicherungsort und „aus 256 werden 128 Bit“.
- #38 „?“ mit geschütztem Leerzeichen und Wortverbindern (`\u{00A0}„\u{2060}?\u{2060}“\u{00A0}`); Blatt sagt „ergänzt“.
- #39 „Notfallcode prüfen“ so breit wie die Spalte (560 pt, Code in 13 pt).
- #40 „Ausserhalb dieses Macs“ nur bei iCloud, Netzlaufwerk oder auswerfbarem/entfernbarem, nicht internem Volume, das
  kein Disk-Image ist (DiskArbitration; gemessen: eingebundenes DMG meldet internal = nil, Modell „Disk Image“). Im
  Zweifel nein (die Mahnzeile bleibt).
- #41 Texte ohne „endgültig“ (Sicherungen behalten Einträge und Verlauf); neu „Ältere Sicherungen entfernen…“ unter
  Einstellungen → Sicherungen (Master-Passwort + Faktoren, dann `purgeBackups`).
- #43 Passwort und 2FA-Geheimnis bestehender Einträge starten im Bearbeiten verdeckt (Punkte + Auge, Klick zeigt das
  Feld); neu angelegte und nach „Übernehmen“ sichtbar.
- #48 Stärke-Wort aus denselben Bit wie die Regel (`PasswordAssessment.level(forBits:)`, eine Schätzung), Bewertung je
  Eingabe zwischengespeichert (`AssessmentCache`).

### Integration (Stufe B)

1. Mit dem echten Kern: `TOTP.parse` liefert dann Codes; die Snapshots schalten `DemoTOTP` automatisch ab und prüfen
   die RFC-6238-Vektoren gegen den Kern. Annahme: `TOTP.code(p, at: Date(timeIntervalSince1970: 0)).remaining`
   ist die Periode (Restzeit = Periode − t mod Periode).
2. `exportKeePass` schreibt in `<Ordner>/Siegel-Export-<Datum>.noindex/` (Annahme der Oberfläche für den Text der
   Passwort-Seite; die Fertig-Seite zeigt den echten Pfad).
3. `securityReport()` sollte schnell sein (Metadaten); die Oberfläche rechnet ihn nach jeder Änderung im Hintergrund.
4. Die v3.1-Attrappe speichert `totp` nicht dauerhaft (verschwindet nach Sperren); der v4-Kern muss es tun.
5. Kern-Anteile der Befunde, die die Oberfläche nicht lösen kann (siehe Übergabe, spec_issues): `recover(kdf:)`
   Standardwert (#21), `acceptOlderFile()` als sauberere Lösung für #28/#33, Argon2 unter dem Schreib-Lock (#36),
   `PasswordStrength.level(forBits:)` öffentlich (#48).
6. Manuell (PRUEFLISTE): Frage beim Beenden mit liegender CSV-Datei (auch nach Schliessen des Fensters), DiskArbitration
   in der Sandbox (USB-Stick → „ausserhalb“, DMG → nicht), ⌘L mit fast voller Platte.

## Integration v4 mit echtem Kern und SiegelHardware (17.10.2026)

Die Attrappe ist verworfen; die Oberfläche läuft gegen den echten Kern (§22 + Zusätze v4.1) und SiegelHardware.
Snapshots: 152 Bilder, alle Prüfungen grün (Hardware bleibt dort `DemoHardware`, jetzt mit echtem Software-P-256 für
den Eintrags-Schlüssel, weil der Kern dessen öffentlichen Schlüssel prüft und ECDH rechnet).

- **async-Varianten mit Provider**: `heavyAsync`/`backgroundAsync` (AppModel.swift). Neues Kit (`kitConfirm` →
  `commitRecovery(_:confirmation:entryFactors:)`), Stufenwechsel (`changeSecurityLevel(…, entryFactors:)`),
  CSV- und KeePass-Export rufen immer die async-Variante mit `UIEntryFactorProvider`; der Kern fragt nur, wenn
  versiegelte Einträge eine Freigabe brauchen (eine pro Notfall-Gruppe). Abbruch der Freigabe →
  `Fehlertexte.protectedEntriesRelease`, Bestätigung bleibt stehen.
- **Vorhandene Karte / vorhandener Schlüssel im Assistenten**: gehen als `currentFactors` an den Kern
  (`SecurityWizardState.currentFactors`), nicht als neues Material – so prüft der Kern Kennung bzw. Prüfwert
  (`wrongCard`/`wrongPassword`) und ersetzt keinen Eintrags-Faktor. Stufe 5 mit einem schon für Einträge
  eingerichteten Schlüssel: „Vorhandenen Schlüssel berühren“ (`wizardTouchExistingKey`, über
  `vault.securityKeyCredential`), keine Neuregistrierung.
- **Notfallweg mit Teilen über die Sicherungen**: `checkRecoverySharesAgainstBackups` und
  `recoverFromNewestReadableBackup(shares:)` (wie beim einzelnen Code). Befund #22: meldet die Prüfung `corruptFile`
  und passt keine Sicherung → Bildschirm „Tresordatei beschädigt“. Befund #42: volle Länge, aber nicht korrigierbar →
  eigener Text (`Fehlertexte.recoveryCode`), Fehlerzeile mit reservierter Höhe und Abstand zur Knopfreihe.
- **Einstellungen → Notfallcode prüfen** mit zwei Teilen (Stufen 4/5, `checkRecoverySharesInSettings`,
  `confirmExistingRecovery(shares:)`). Die Zeile der Stufe zeigt das Notfall-Schema des **Kits** (Kopf) – nach einer
  Wiederherstellung mit Teilen ist das Stufe 1 mit „2 von 3 Teilen“, bis ein neues Kit geschrieben wird; der
  Stufenwechsel verlangt dann ein neues Kit (Schritt „Notfallkit“).
- **Fehlertexte**: alle festen Codes des Kerns und der Hardware (`entry.sealedSecrets/protection/stale/totpTooLong`,
  `factor.*`, `se.verify`, `hw.*`, `export.kdbx`) und die 12 `totp.*`-Codes; Anlässe `migration-v1`/`stufenwechsel`.
- **2FA**: Periode direkt aus `TOTP.Parameters.period`; Sichern meldet den Grund aus `TOTP.parse`.

## Selbstvernichtung (v4.3, 17.10.2026)

Gebaut gegen eine Attrappe der §23.3-Schnittstelle, bei der Integration (17.10.2026) auf den echten Kern umgestellt
(die Attrappe ist verworfen). Die Oberfläche nutzt die Zusätze des Kerns zu §23.3: `configureDestruction(…,
entryFactors:)` (async, gibt `PurgeReport?` zurück), `UnlockedVault.destructibleEntries`, `destructionSettings`,
`destructionKeyID`, `destructionStatus` (sitzungsgerecht), `store.destructionKeyEraser`.

### Neue Dateien

| Datei | Inhalt |
|---|---|
| `Modell/Selbstvernichtung.swift` | `DestructionAccess` (einziger Zugriff auf `destructibleEntries`, nicht in §23.3), `DestructionRules` (Grenzen 7–365 / 10–100, Auswahl, VERNICHTEN, Frist ab 25 % Restzeit, Warnung ab N/2), `DestructionTexts` (alle Texte, Fehler), `DestructionState` (Entwurf + Bestätigung, Geheimnisse nur bis `wipe()`), `DestructionBanner` |
| `Modell/AppModel+Selbstvernichtung.swift` | Zustand lesen (`readDestructionSession`, `refreshDestructionStatus`), Totmann-Prüfung (`checkDeadmanNow`, `deadmanTick`, 10-Minuten-Takt, Aktivieren, Aufwachen), Anzeigen (`lockDeadline`, `lockRemainingAttempts`, `destructionBanner`), Banner „Entfernen“, Einstellungen (`showDestruction`, Entwurf, `destructionContinue`, `destructionApply`), `discardDestructionKey` |
| `Bildschirme/SelbstvernichtungView.swift` | `DestructionPage` (Entwurf, Bestätigung), `DestructibleRow`, `CheckGlyph`, `DestructionAttemptsWarning`, `DestructionDeadlineHint`, `DestructionBannerView`, `DestructibleMark` |
| `SiegelSnapshots/Selbstvernichtung.swift` | Bilder 139–158, Prüfungen (Regeln, Abfolge, Duress, Banner, Totmann) |
| `SiegelSnapshots/KernBruecke.swift` | Frist und Zähler für Bilder: ändert `lastGenuineUnlock`/`failedAttempts` in `Hardware/zustand.json` (Release-Bau, keine Testschalter); `kernStatus` baut einen `DestructionStatus` für die Regel-Prüfungen |

Geändert: `AppModel` (Zustände, `startDeadmanChecks`, `destructionConfigured`, `wireDestructionKeyEraser` im Init und
in `snapshotUseHardware`), `AppModel+Ablaeufe`
(`loadLockHeader` prüft zuerst den Totmann-Schalter und liest den Zustand; `submitUnlock` prüft vor jedem Versuch,
liest danach den Zähler neu; Doppel-Enter-Sperre `UnlockState.preparing`), `LockReason.deadman`, `FactorHardware.
destroySecureEnclaveKey`, `SettingsState.Page.destruction`, `SettingsView` (Zeile in „Sicherheitsstufe“, nur Stufe 4/5),
`LockView`, `StatusZeilen`/`VaultView` (Banner), `EntryDetailView` (Markierung, Vernichtet-Leiste), `EntryEditView` +
`ProtectionPicker` (`minimum`: vernichtbare Einträge nicht unter Schutz 4), `AppModel+Schutz` (vernichtete Einträge
lassen sich nicht aufdecken, ohne Faktor-Abfrage), `LevelTexts.rulesLong` (Stufe 4/5), `Fehlertexte` (`hw.destroy`,
`entry.destroyed`, `destruction.*`), `SicherheitsstufeView`/`startLevelChange` (Stufe < 4 gesperrt, solange die
Selbstvernichtung eingerichtet ist: `blocksLevelChange`), `RecoveryFlowView` (Hinweis: vernichtbare Einträge fallen
beim Notfallweg weg).

### Wie es abläuft

- **Prüfen** (§23.2): `checkDeadman(now:)` beim Start (im Hintergrund vor dem Kopf des Sperrbildschirms; Entsperren
  wartet immer auf eine eigene Prüfung), vor jedem Entsperr-Versuch (unabhängig vom Passwort), beim Aktivieren, nach
  dem Ruhezustand und alle 10 Minuten (Timer im `.common`-Modus, auch gesperrt). Vernichtet er während einer offenen
  Sitzung → `lock(reason: .deadman)`.
- **Sperrbildschirm**: unten dezent „Frist endet am …“ (ab 25 % Restzeit; als Hintergrund des Notfallweg-Knopfs, das
  Logo springt nicht), in der Meldungszeile deutlich „Noch x Versuche bis zur Vernichtung“ (ab N/2, bis N−1; passt mit
  einer einzeiligen Fehlermeldung in die festen 44 pt). Beide nur aus `destructionStatus()` – nie aus dem Wissen, ob
  vernichtet wurde (die Frist verschwindet nur, weil sie abgelaufen ist).
- **Einstellungen → Sicherheitsstufe → Selbstvernichtung** (nur Stufe 4/5): Auswahl nur Schutz 4/5 (markierte Zeilen
  „Kein Notfallweg“, Hinweis-Kasten oben), Totmann (7/14/30/90/180/365 Tage), Zähler (10/20/30/50/100), Vernichtungs-
  Passwort setzen/ändern/entfernen (MasterPasswordPolicy mit Stärke-Anzeige, Wiederholung), „Alles ausschalten“,
  „Verwerfen“. „Weiter…“ → Bestätigung: Zusammenfassung („30 Tage (bisher aus)“), beim **Einschalten** (neuer Auslöser
  oder neu markierte Einträge) VERNICHTEN abtippen, Master-Passwort, dann alle Faktoren der Stufe; ist ein neuer
  Vernichtungs-Schlüssel V nötig (eingeschaltet, aber `destructionKeyID == nil`: nie eingerichtet oder nach
  „Entfernen“), zuerst `verify` (kein Schlüssel umsonst bei Tippfehlern), dann Touch ID für V (`enrollEntryKey`),
  dann `configureDestruction(…, entryFactors: UIEntryFactorProvider)`: Der Kern prüft Passwort und Faktoren und holt
  zum Neu-Versiegeln eine Freigabe je Notfall-Gruppe (neu markiert) bzw. Touch ID je Eintrag (abgewählt). Neu
  markiert → der Kern entfernt ältere Sicherungen (`PurgeReport`: `notePurgeReport`, Warnung bei Rest). Scheitert das
  Schreiben oder wird gesperrt, wird der neue V mit `destroy` vernichtet. Vernichtungs-Passwort = Master-Passwort →
  abgelehnt, bevor ein Faktor abgefragt wird. Nach einer Vernichtung ist die Seite bis „Entfernen“ gesperrt (der Kern
  lehnt sonst mit `io("destruction.destroyed")` ab); „Entfernen“ schaltet die Selbstvernichtung ganz aus.
- **Nach einer Vernichtung** (echte Sitzung): Banner unten in der Seitenleiste „n Einträge wurden vernichtet“ / Auslöser
  / Datum mit „Entfernen“ (`removeDestroyedEntries`); vernichtete Einträge zeigen im Detail „Vernichtet · Auslöser,
  Datum“, Passwort/Notizen „Vernichtet“, kein Aufdecken, kein Bearbeiten; die Seite der Einstellungen zeigt dasselbe.
- **Vernichtungs-Sitzung**: kommt als gewöhnliches `.unlocked`; die Oberfläche verzweigt nur, um nichts zu zeigen
  (`isDuressSession` → keine Markierungen, kein Banner; angezeigter Zustand aus `vault.destructionStatus`, der in
  dieser Sitzung nichts verrät). Gleiche Faktor-Abfolge (Snapshots prüfen das Protokoll der Hardware-Attrappe:
  Touch ID, Karte – bei echtem und Vernichtungs-Passwort identisch). Die vernichteten Einträge blendet der
  Kern aus (die Oberfläche kennt sie in dieser Sitzung nicht). Die Fusszeile der Auswahl ist neutral formuliert
  („Keine Einträge ausgewählt.“), weil sie in der Vernichtungs-Sitzung so erscheint.
- **Detail**: dezent „· Vernichtbar“ (Flammen-Symbol, Tooltip) nach „Schutz 4 · Maximal“.

### Integration (v4.3, erledigt)

- Attrappe verworfen; `submitUnlock` ruft wieder direkt `store.unlock` (der Kern zählt, prüft den Totmann-Schalter und
  erkennt das Vernichtungs-Passwort). `snapshotUseUnlock` ist entfernt.
- `store.destructionKeyEraser` = `FactorHardware.destroySecureEnclaveKey` (App: `SecureEnclaveFactor.destroy`,
  Snapshots: Hardware-Attrappe).
- Entwurf: Basis ist der Inhalt (`DestructionState(…, keyAvailable: destructionKeyID != nil)`), neue Einstellungen
  über den öffentlichen Init `DestructionSettings(deadmanDays:maxFailedAttempts:duressEnabled:)`.
- Sperrbildschirm-Regeln über die Helfer des Kerns (`deadlineIsNear`, `shouldWarnAboutAttempts`,
  `remainingAttempts`); abgelaufene Frist und 0 verbleibende Versuche zeigen nichts.
- Snapshots 139–158 mit dem echten Kern neu gerendert und angesehen; nach „Entfernen“ wählt das Szenario die Auslöser
  neu (der Kern schaltet alles aus), beim Markieren wird die Karte für die Notfall-Gruppe ein zweites Mal geliefert.

### Offen (v4.3)

- In der Vernichtungs-Sitzung zeigt die Seite der Einstellungen die Auslöser wie eingestellt, aber keine markierten
  Einträge (sie sind weg); jede Änderung dort scheitert mit „Passwort stimmt nicht“ (der Kern behandelt das
  Vernichtungs-Passwort als falsch, ehrliche Grenze in KERN-NOTIZEN).
- Manuell (PRUEFLISTE): echter Touch-ID-Dialog beim Anlegen von V und bei der Freigabe je Notfall-Gruppe; Totmann nach
  Ruhezustand (Takt + Aufwachen); Vernichtungs-Passwort mit echter Hardware (gleiche Dauer, gleiche Dialoge);
  Bildschirmaufnahme des Sperrbildschirms; VoiceOver der Auswahlzeilen.

## Datei-Befunde (v4.4)

- `RecoveryState.origin` (`.lock`, `.missingVault`, `.file(URL)`): „Tresor fehlt“ → `missingUseRecovery()` (gewählte
  Datei → `startRecovery(file:)`, sonst neueste passende Sicherung); „Beschädigt“ → `corruptUseRecovery()`;
  Einstellungen → „Sicherung einspielen…“ → `backupImportUseRecovery()` (sperrt, dann Notfallweg für die Datei).
  `cancelRecovery()` → `route()`. Einrichtung „Aus Sicherung wiederherstellen…“ und „Andere Sicherung wählen…“ →
  `chooseBackupFileForRestore()` / `useBackupFileForRestore(_:)` (`MissingVaultState.chosenFile`, `fromSetup`).
- Code oder Teile: `RecoveryState.setHeader(_:certain:)`; nur ein geprüfter Kopf der Zieldatei ist „sicher“, sonst
  Umschalter (`recoveryChooseShares`) und `RecoveryCodeField.onOverflow` (56 Zeichen → Teile).
- Selbstvernichtung: nach einem Fehler V nur über `discardUnusedDestructionKey` (Kern bestätigt „unbenutzt“), in
  `whenDiscarded(.failure)` nie. `purgeNotice` kennt `interrupted`.
- Zähler-Warnung (`DestructionAttemptsWarning`) auch bei „Tresor fehlt“, „Beschädigt“, „Sicherung einspielen“;
  `refreshDestructionStatus()` nach jedem `wrongPassword` dort, `route()` liest beim Betreten neu.
- Snapshots 170–182 (`DateiBefunde.swift`, einzeln: `SIEGEL_SNAPSHOTS_NUR=DATEI`).

## Hygiene-Befunde (v4.4)

- hygiene-1: `writeDraft` → `draftProtection` / `writeSealedDraft` / `writeOpenDraft` (`AppModel+Tresor.swift`),
  Hinweise `protectionNotice` und `secretsLostNotice` (ohne Eintragsnamen, sie stehen auf dem Sperrbildschirm).
- hygiene-2: `lock(reason:)` leert die Zwischenablage nur bei `reason != .deactivated`; `AutoLock.fire` leert vor
  `isArmed`; `SecretPasteboard` hält eine Aktivität gegen App Nap, bis `forget` läuft.
- hygiene-3: `SecretPasteboard.fieldCopyLifetimeProvider` (gesetzt in `AppModel.init` über
  `installFieldCopyLifetime`), ohne Provider 15 s; keine globale Dauer mehr in `AppSettings`.
- hygiene-4: `CardScanSheet` legt `CameraPreview` in ein `SecretGate` (`CameraPreviewHidden`: Texte über und unter
  dem Sucher, „Hier zeigen“ in der Mitte).
- hygiene-5: `DestructionRules.showsDeadline` → nil, sobald `destroyedAt` vermerkt ist.
- Snapshots 190–193 (`HygieneBefunde.swift`; Probe B und Totmann während der Bearbeitung in `Selbstvernichtung.swift`;
  einzeln: `SIEGEL_SNAPSHOTS_NUR=HYGIENE`). `SecretPasteboardProbe` (SPI) setzt nur den Merker mit fremdem
  `changeCount` – die echte Zwischenablage bleibt unberührt. `DemoScanner.vorschau` liefert eine Attrappe des
  Kamerabilds.

### Ablauf-Befunde der zweiten Prüfung (v4.4, ablaeufe-1 bis ablaeufe-10)

- ablaeufe-1/-2/-6/-8/-9 waren schon mit hygiene-1/-2, datei-5, hygiene-3 und hardware-1 behoben; Ergänzungen unten.
- ablaeufe-3: `lock()` setzt `destruction = nil` (und zählt `destructionLoads` hoch); `route()` → `loadLockHeader`
  liest den Stand aus `zustand.json`. `deadmanTick` liest nach seiner Sperre selbst neu.
- ablaeufe-4: `UIEntryFactorProvider(model:)` merkt sich `epoch`; jede Abfrage prüft zuerst
  `model.isCurrentSession(epoch)` (gleiche `epoch`, Tresor offen – nicht `isUnlocked`, das Notfallkit läuft auf
  `.recoveryKit`) → sonst `factorCancelled`. Im Kern `LockCheckedEntryFactors` (`io("vault.locked")`).
- ablaeufe-5: `DestructionRules.isConfigured(status)` (Auslöser oder `keyConfigured`) für den Hinweis im Notfallweg;
  `DestructionTexts.summary(_:configured:)` mit `destructionConfigured`; Hinweis `marksWithoutTrigger` im Entwurf.
- ablaeufe-6: `countsAttempt(_:)` hängt bei aktivem Zähler „Auch hier zählt jeder Fehlversuch.“ an die Meldungen der
  Sicherungswege.
- ablaeufe-7: `presentSettings()` (ohne die Sperre aus #36) nur für `startEnroll(fromEditor: true)`.
- ablaeufe-8: `lastClipboardMax` (wie `lastAutoLockMax`) für `effectiveClipboardSeconds` im gesperrten Zustand.
- ablaeufe-10: `route()` → `mayHaveBackups` (nur Verzeichnisse) → sonst `.missingVault` mit
  `MissingVaultState.searching` und `loadBackups(into:setupIfNone:)` im Hintergrund (`searchRun` verwirft Älteres);
  `BackupSearchView` zeigt „Sicherungen werden gesucht…“ erst nach 0.4 s. `openNewestReadableBackup` liest die Liste
  über `heavy`.
- Snapshots 230–233 (`AblaeufeBefunde.swift`; ablaeufe-3 in `Selbstvernichtung.swift`, ablaeufe-7 in
  `Haertestufe.swift`, ablaeufe-6 in `DateiBefunde.swift`; einzeln: `SIEGEL_SNAPSHOTS_NUR=ABLAEUFE`).

### Design-Befunde der zweiten Prüfung (v4.4, design-1 bis design-7)

- design-1 = ablaeufe-7 (schon behoben).
- design-2: `LockView` – Frist als eigene Zeile, Logo-Abstand `Spacer(minLength: 24).frame(maxHeight:)` mit
  `layoutPriority(1)`. `layoutProbe(_:)` (Theme/LayoutProbe.swift) meldet Rahmen nur, wenn SiegelSnapshots einen
  `LayoutRecorder` über `snapshotLayoutRecorder` setzt (`shot(…, messen:)`). Die Bedienungshilfen-Struktur von
  SwiftUI ist offscreen leer, darum dieser Weg.
- design-3: `BackupTexts` (öffentlich, FlowView.swift) nach `vaultHeader.factors`/`recoveryScheme`.
- design-4: `CardScanState.typingMessage` (`defaultTypingMessage`), `scanCard(…, typingMessage:)`.
- design-5: `ProtectionPickerMetrics` als eine Quelle für Ansicht und Längenprüfung (`ProtectionPickerProbe`, SPI).
- design-6/-7: `LevelTextsProbe` (SPI) mit `rules`, `rulesLong` und allen Sätzen zur Secure Enclave.
- Snapshot 68b (Sicherung exportieren in Stufe 4) neu; 86c folgt dem echten Weg „Code zur Bestätigung abtippen…“.

## Offene Punkte

- Systemmenüs: `build.sh` setzt `CFBundleDevelopmentRegion = de` und `CFBundleLocalizations = [de]`.
- Einfügen ins Master-Passwort-Feld wird über `controlTextDidChange` + `NSApp.currentEvent` erkannt.
- Manuell prüfen (PRUEFLISTE): CGWindowList `kCGWindowSharingState == 0` auch mit Sheet/Druck-/Öffnen-Panel;
  ⌘C aus `SecretField` erscheint nicht im Zwischenablage-Verlauf; Sidecar verdeckt; VoiceOver liest
  „Passwort, verborgen“; Tastatur in der Liste (Pfeile, Enter, Esc) und ⌘F/⌘N/⌘E/⇧⌘C im echten Fenster.
- Ganz-Schrift-Verwechslungen (z. B. ein rein kyrillischer Host, der wie ein lateinischer aussieht) erkennt
  `ScriptCheck` nicht; dafür bräuchte es die Unicode-Confusables-Liste.
- Ein Test-Ziel für SiegelUI (z. B. `SiegelUITests`) fehlt im Paket; die UI-Logik wird im Snapshot-Programm geprüft.
- `DEBUG`-Bau: `SIEGEL_DEBUG_DIRECTORY=<Ordner>` erlaubt Starten ohne Sandbox; im Release-Bau ohne Wirkung.
