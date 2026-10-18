# Autofill für Siegel (vorbereitet, SPEC §20)

Siegel kann Passwörter in Safari und anderen Apps über die AutoFill-Schnittstelle von macOS einsetzen. Der Code
dafür liegt hier bei, wird aber **nur mit einem bezahlten Apple-Entwicklerkonto** gebaut: Das Entitlement
`com.apple.developer.authentication-services.autofill-credential-provider` bekommt das kostenlose Team nicht
(gemessen am 16.10.2026 mit einer Probe: «Communication with Apple failed: The selected team does not have a
program membership that is eligible for this feature»). Die normale App aus `./build.sh` ist davon nicht
betroffen; sie bleibt ad-hoc signiert mit genau sechs Entitlements und ohne Erweiterung.

## Inhalt

| Datei | Zweck |
|---|---|
| `project.yml` | XcodeGen-Projekt: App `SiegelMac` (Produkt `Siegel.app`) + Erweiterung `SiegelAutofill`; das SwiftPM-Paket des Projekts ist lokale Abhängigkeit |
| `SiegelAutofill/CredentialProviderViewController.swift` | `ASCredentialProviderViewController`: Master-Passwort, Touch ID, Trefferliste, Auswahl |
| `SiegelAutofill/AutofillSitzung.swift` | Tresorzugriff (nur lesen), Gruppen-Container, Faktoren beim Aufdecken |
| `SiegelAutofill/Info.plist`, `SiegelAutofill.entitlements` | Erweiterung: Sandbox, App-Gruppe, Autofill |
| `App/Siegel-Autofill.entitlements` | App in dieser Variante: die sechs aus SPEC §21 + App-Gruppe + Autofill |

Die App nutzt dieselbe `skripte/Info.plist` wie `build.sh` und baut das Icon mit `skripte/icon_bauen.sh`.

## Bauen

```
skripte/autofill_bauen.sh                          # ohne Team: nur Kompilierprüfung (CODE_SIGNING_ALLOWED=NO)
SIEGEL_TEAM_ID=ABCDE12345 skripte/autofill_bauen.sh  # mit bezahltem Konto: signierter Bau
```

Voraussetzungen: Xcode (`/Applications/Xcode.app`), XcodeGen (`brew install xcodegen`) und in `Package.swift` die
Bibliotheks-Produkte `SiegelCore`, `SiegelHardware`, `SiegelUI` (sonst bricht das Skript mit einem Hinweis ab).
Ergebnis: `build/autofill/DD/Build/Products/Release/Siegel.app` mit `Contents/PlugIns/SiegelAutofill.appex`. Das
Skript installiert nichts. Mit Team prüft es die Signatur und die Entitlements beider Bündel (kein
`get-task-allow`: `CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO`).

## Was die Erweiterung tut

1. Liest nur den Kopf des Tresors (`VaultStore.inspect()`, kein Argon2). Stufe 4 oder 5 (Karte oder
   Sicherheitsschlüssel im Kopf) → Hinweis «Dein Tresor hat die Stufe … Passwörter gibt es dort nur in der App.»
2. Master-Passwort, bei Stufe 2/3 zusätzlich Touch ID (`SecureEnclaveFactor.secret`, «Siegel entsperren»).
3. Zeigt nur Einträge, die `AutofillMatcher.matches(entryURL:serviceIdentifier:)` für die Seite meldet **und**
   deren Schutz Autofill erlaubt (Normal, Fingerabdruck; ab Schutz Hoch nie). Nur bis Tresor-Stufe 3
   (`policy.autofillAllowed`).
4. Bei Auswahl: Schutz Fingerabdruck → Touch ID über `revealSecrets` (jedes Mal). Danach wird der Tresor sofort
   gesperrt; nach 120 s ohne Auswahl ebenfalls (Abbruch).
5. `provideCredentialWithoutUserInteraction` füllt nie still aus (`userInteractionRequired`). Siegel hinterlegt
   keine Kennungen beim System (`ASCredentialIdentityStore`), damit keine Titel oder Benutzernamen den Tresor
   verlassen; darum erscheint Siegel nicht in der QuickType-Leiste, sondern über «Passwörter…» → Siegel.
6. Schreibt nie: kein Speichern, keine Migration. Das eigene Fenster bekommt `sharingType = .none`; ob das bei der
   vom System gehosteten Ansicht wirkt, ist ein Punkt der Prüfliste.

## Gruppen-Container und Umzug des Tresors (nötig, bevor Autofill etwas findet)

Die Erweiterung hat einen eigenen Sandbox-Container und sieht den Tresor der App dort nicht. Gemeinsam ist nur der
Gruppen-Container der App-Gruppe `<TEAM-ID>.com.aralim.siegel`:

| | Pfad |
|---|---|
| heute (`./build.sh`, ad-hoc) | `~/Library/Containers/com.aralim.siegel/Data/Library/Application Support/Siegel/` |
| Autofill-Variante | `~/Library/Group Containers/<TEAM-ID>.com.aralim.siegel/Library/Application Support/Siegel/` |

Der Pfad innerhalb des Gruppen-Containers ist die Konstante `AutofillOrt.tresorOrdner`
(`Library/Application Support/Siegel`); die Gruppen-Kennung setzt Xcode beim Bauen in die Info.plist der
Erweiterung (`SiegelAppGroup = $(TeamIdentifierPrefix)com.aralim.siegel`). Rollback-Merker liegen gemeinsam in
`UserDefaults(suiteName: "<TEAM-ID>.com.aralim.siegel")`.

**Noch nicht umgesetzt** (gehört in Kern/App, nicht in die Erweiterung). Die App der Autofill-Variante muss beim
Start den Tresor umziehen, sonst findet die Erweiterung «Kein Tresor»:

1. `VaultStore.defaultDirectory()` liefert den Gruppen-Ordner, wenn
   `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)` für `<TEAM-ID>.com.aralim.siegel` einen Ordner
   liefert (nur die team-signierte Variante hat das Gruppen-Entitlement); sonst wie bisher den Sandbox-Container.
2. Liegt im Gruppen-Ordner kein `Tresor.siegel`, aber im Sandbox-Container: zuerst eine angeheftete Sicherung
   `vor-umzug` im alten Ordner, dann `Tresor.siegel`, `Sicherungen/` und `Hardware/` (Secure-Enclave-Blobs) in den
   Gruppen-Ordner kopieren (`clonefile`, Ordner 0700, Dateien 0600), jede Datei zurücklesen und Byte für Byte
   vergleichen, Prüfsumme des Tresors prüfen. Erst dann den alten Ordner in `Siegel-vor-Umzug` umbenennen –
   **nie löschen**. Scheitert ein Schritt, bleibt alles am alten Ort und die App meldet es.
3. Rollback-Merker (`Siegel.rollback.<vaultID>`) aus `UserDefaults.standard` in die Gruppen-Einstellungen
   übernehmen (jeweils den grösseren Wert), danach liest und schreibt die App nur noch dort.
4. Einzelinstanz-Sperre `.lock` und Einstellungen (`@AppStorage`) bleiben in der App; die Erweiterung nimmt keine
   Sperre, sie liest nur (Speichern ersetzt die Datei per `rename`, das Lesen sieht immer eine ganze Datei).
5. **Rückweg** zur ad-hoc-App aus `./build.sh`: Sie hat keine App-Gruppe und sieht den Gruppen-Ordner nicht
   («Tresor fehlt»). Vorher den Tresor zurückziehen (gleiches Verfahren umgekehrt) oder eine verschlüsselte
   Sicherung exportieren und in der ad-hoc-App einspielen.
6. Danach Autofill einschalten: App nach `/Applications`, einmal starten, Systemeinstellungen → Allgemein →
   AutoFill & Passwörter → «Siegel».

## Offene Punkte

- Mit echtem bezahltem Konto ungetestet (Prüfliste `PRUEFLISTE.md`, Abschnitt «Autofill»).
- Argon2 mit 1–2 GiB in einem Erweiterungsprozess: Speichergrenzen für Erweiterungen unter macOS prüfen (unter iOS
  wären es rund 120 MB; dort ginge das so nicht).
- Ob Secure-Enclave-Blobs, die die App erzeugt hat, im Prozess der Erweiterung funktionieren (anderer Prozess,
  gleiche Team-Signatur): prüfen. Sonst bei Stufe 2/3 «Touch ID ist für diesen Tresor nicht verfügbar».
