# Siegel – Prüfliste (manuelle Prüfungen)

Ergänzt die automatischen Prüfungen (SPEC §10, `PRUEFBERICHT.md`). Stand 17.10.2026, SPEC v4.4. Vor jeder
Weitergabe und nach Änderungen an Fenstern, Feldern, Zwischenablage, Drucken oder Faktoren einmal durchgehen.

**Nur mit einem Testtresor** und erfundenen Einträgen prüfen, nie mit echten Passwörtern. Stand 17.10.2026 liegt im
App-Container noch kein Tresor (nur `.lock`), der Testtresor darf also im normalen Benutzerkonto entstehen. Gibt es
schon einen echten Tresor, Teil A und B in einem **zweiten macOS-Benutzerkonto** durchgehen: Die App hat nur einen
Sandbox-Container pro Benutzer. Ausserdem macht eine Änderung der Fingerabdrücke (A7) jeden Touch-ID-Schlüssel dieses
Benutzers unbrauchbar.

Reihenfolge:

- **Teil A** zuerst, zu zweit mit Aralim (Finger, Drucker, Karte, Kamera, Entscheidungen), in der angegebenen
  Reihenfolge. Die Abschnitte bauen aufeinander auf; A7 setzt den Testtresor auf Stufe 1 zurück und kommt darum zum
  Schluss.
- **Teil B** danach, mit dem Testtresor.
- **Teil C**, sobald zusätzliche Hardware, ein Konto oder ein Programm da ist.
- Am Ende **Z**: Testdaten wegräumen.

| Datum | macOS | Siegel-Build | Geprüft von | Teil/Abschnitte | Ergebnis |
|---|---|---|---|---|---|
| | | | | | |

Vorbereitung: `./build.sh run`. Die Skripte brauchen `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`
(oder die Command Line Tools) für `swift`.

Frühere Nummern (bis 17.10.2026, z. B. in `PRUEFBERICHT.md` «§18–§20»): Die alte Nummer steht bei jedem Abschnitt
als «früher §n». §18–§20 (Befunde der zweiten Prüfung) sind auf A5, A6, A7 und C4 verteilt; jeder Punkt nennt seinen
Befund.

## 0. Automatisch (nur kontrollieren, dass es grün war) – früher §0

- [ ] `swift test` grün (auch in der CI: `.github/workflows/tests.yml`, Abbild macos-26)
- [ ] `./build.sh` ohne Fehler:
  - [ ] Grep-Sperren samt Selbsttest (SiegelCore, SiegelUI, SiegelHardware, Siegel, Erweiterungen/SiegelAutofill)
  - [ ] `codesign --verify --strict`
  - [ ] genau die sechs Entitlements aus §21 (app-sandbox, files.user-selected.read-write, files.bookmarks.app-scope,
        print, device.camera, device.usb), kein `get-task-allow`, Flags `adhoc,runtime`
  - [ ] `otool -L` ohne sodium und `/opt/homebrew`
  - [ ] genau die erwarteten Info.plist-Schlüssel samt `NSCameraUsageDescription`
  - [ ] Bündelinhalt genau: `Contents/Resources` nur `Assets.car` und `Siegel.icns`, kein `*.bundle`, keine `Fixtures`
- [ ] `skripte/sanitizer.sh` grün: AddressSanitizer und ThreadSanitizer, je «ok» mit allen Tests
- [ ] `skripte/autofill_bauen.sh` (ohne `SIEGEL_TEAM_ID`): «kompiliert, unsigniert»
- [ ] Probe ohne die echte App: `SIEGEL_INSTALL_DIR=/tmp/siegel-probe ./build.sh` baut und prüft, ohne
      `~/Applications/Siegel.app` und eine laufende Siegel-Instanz anzufassen
- [ ] `referenz/gegenprobe.sh` → «alles stimmt»

---

# Teil A – zuerst mit Aralim zusammen

## A0. Vorbereitung

- [ ] Container leer bzw. nur Testdaten: `ls -la ~/Library/Containers/com.aralim.siegel/Data/Library/Application\ Support/Siegel/`
      → nur `.lock` (sonst: zweites Benutzerkonto, siehe oben)
- [ ] Echter Secure-Enclave-Grundtest ohne Dialog: `SIEGEL_HW_MANUELL=1 swift test --filter Manuell` → besteht
      (Touch ID verfügbar, Schlüssel lässt sich erzeugen)
- [ ] Bereitlegen: Drucker (Geräte-URI notieren: `lpstat -v`), festes Papier für die Karte, Schere, Notizpapier und
      Stift für Notfallcode und Teile, ein Couvert «TESTTRESOR – kein echter Code»
- [ ] FileVault-Status notieren (`fdesetup status`): ______________________
- [ ] Ein Testpasswort aus der Passphrase-Funktion verwenden und auf dem Notizpapier als Testpasswort kennzeichnen

## A1. Testtresor und Notfallkit (Stufe 1) – früher §6, teilweise

- [ ] Einrichtung: «Passphrase vorschlagen», «Neu würfeln» ein paarmal, Passphrase bestätigen → «Tresor anlegen»;
      feine Fortschrittslinie während Argon2; FileVault-Hinweis nur bei ausgeschaltetem FileVault
- [ ] «Lieber ein eigenes Passwort»: `Sommer2026!!!` wird abgelehnt («nötig: 60 Bit»), eine lange Zufallsfolge
      angenommen (nur ansehen, dann zurück zur Passphrase)
- [ ] Notfallkit: Code in 11 Gruppen, Kit-Kennung; Warntext sichtbar; kein Kopieren, kein PDF-Knopf
- [ ] «Drucken…»: Druckdialog **ohne Vorschau**; nach der Wahl des Druckers ggf. die Druckerwarnung; Blatt kommt mit
      Code und Kit-Kennung; Auftragsname in der Warteliste «Dokument»
- [ ] Gleich danach im Druckdialog «PDF ▾» → «Als PDF sichern…»: Das PDF enthält **keine Codegruppe**, sondern
      «Notfallkit nur auf Papier – Code nicht enthalten»; Siegel meldet nicht «Gedruckt». PDF danach löschen
- [ ] Warteliste nach dem Druck leer (Systemeinstellungen → Drucker & Scanner → Warteliste)
- [ ] Bestätigung: zwei zufällige Gruppen; eine falsche Gruppe → Fehlermeldung, nichts bestätigt; richtige → fertig
- [ ] Tresor: drei bis fünf Testeinträge anlegen (Titel, Benutzer, Passwort aus dem Generator, Website, Notiz), einer
      davon mit 2FA-Geheimnis `JBSWY3DPEHPK3PXP` → Code mit Restsekunden erscheint
- [ ] Einstellungen → «Notfallcode prüfen…» mit dem abgeschriebenen Code → «passt zu diesem Tresor»; mit einem
      absichtlich vertauschten Nachbarpaar → Korrekturvorschlag mit markierten Stellen

## A2. Touch ID / Secure Enclave echt (SPEC §14.1, Stufen 2 und 3) – früher §10

- [ ] **Einrichten**: Stufe 2 «Erhöht» wählen → Assistent → Touch-ID-Dialog «Siegel …» erscheint genau einmal zur
      Prüfung; danach liegt `Application Support/Siegel/Hardware/<seKeyID>.siegelhw` (0600, `ls -l`) und **nicht**
      in der Tresordatei; die Einstellungen zeigen Stufe 2
- [ ] Schlüsseldatei vom Backup ausgenommen: `tmutil isexcluded <Datei>` → excluded
- [ ] Einrichten abbrechen (Touch ID «Abbrechen») → nichts geschrieben, Tresor bleibt Stufe 1 (vor dem eigentlichen
      Einrichten prüfen)
- [ ] **Entsperren**: Master-Passwort + Touch ID → offen. Touch ID abbrechen → «Touch ID abgebrochen», kein Entsperren,
      kein Absturz; «Erneut versuchen» geht. Falscher Finger (dreimal) → Systemmeldung, kein Entsperren
- [ ] Touch ID wird jedes Mal verlangt (keine Wiederverwendung, `touchIDAuthenticationAllowableReuseDuration = 0`):
      zweimal kurz hintereinander sperren/entsperren → zweimal Dialog
- [ ] **Sperre ist kein verlorener Schlüssel** (v4.4): fünfmal einen falschen Finger auflegen, bis macOS Touch ID sperrt
      → Siegel meldet «Touch ID ist nach zu vielen Versuchen gesperrt …», bietet **keinen** Notfallweg in der
      Faktor-Zeile an, «Erneut versuchen» ist der Hauptknopf. Bildschirm sperren (⌃⌘Q), mit dem Passwort anmelden,
      erneut versuchen → offen
- [ ] **Deckel zu** (MacBook zugeklappt mit externem Bildschirm und Tastatur ohne Touch ID) → «Touch ID ist gerade
      nicht erreichbar – ist der Deckel zu? …», kein Notfallweg in der Faktor-Zeile; Deckel öffnen, erneut versuchen →
      offen. Ankommenden Fehlercode notieren: ______________________
- [ ] Stufe 3 «Hoch»: Touch ID vor jedem Aufdecken/Kopieren (auch Schutz 1), Sperre beim App-Wechsel (⌘-Tab),
      Zwischenablage höchstens 15 s, Auto-Sperre höchstens 2 Min (Einstellungen lassen mehr nicht zu); Schlüsselableitung
      fest «Stark»
- [ ] Stufe 3: Der Touch-ID-Dialog selbst löst **keine** Sperre beim App-Wechsel aus (Aufdecken → Dialog erscheint →
      Finger → Eintrag aufgedeckt, Tresor bleibt offen)
- [ ] Stufe 3 (v4.4, hygiene-2): Passwort kopieren → ⌘-Tab in den Browser (Siegel sperrt) → ⌘V fügt ein; nach 15 s
      ist die Zwischenablage leer, auch wenn Siegel im Hintergrund bleibt. Kopieren → ⌘-Tab → sofort Bildschirm sperren
      (⌃⌘Q) bzw. Deckel zu → danach ist die Zwischenablage leer
- [ ] Stufe 3: Touch ID gesperrt (wie oben) beim Aufdecken → Hinweis nennt die Sperre, kein Notfallweg
- [ ] **Stufe zurück auf 1**: verlangt Passwort + Touch ID; der Blob ist erst **nach** dem Schreiben entfernt
      (`ls Hardware/` vorher/nachher); danach öffnet das Passwort allein
- [ ] Stufe 1 mit Touch ID für Einträge (falls nicht schon da: Einstellungen → «Faktoren für Einträge» → Touch ID):
      Eintrag mit Schutz 3 bearbeiten, aufdecken, Schutz 4 wählen (Karte «noch einrichten»), Auto-Sperre abwarten →
      Sperrbildschirm «Die offene Bearbeitung ist mit Schutz 3 statt 4 gespeichert …»; nach dem Entsperren **kein**
      zusätzlicher «Entwurf …», der Eintrag verlangt weiter Touch ID (hygiene-1)
- [ ] Dasselbe mit einem Eintrag mit Schutz 2, Schutz 4 wählen, ⌘L → Hinweis «mit Schutz 3 statt 4 gespeichert», kein
      «Entwurf …», der Eintrag verlangt weiter Touch ID (ablaeufe-1)

## A3. QR-Schlüsselkarte und Stufe 4 (SPEC §14.2, §15) – früher §11 und §13, teilweise

- [ ] Stufe 4 «Maximal» wählen: Übersicht zeigt «Was du zum Öffnen brauchst / Was im Notfall»; Assistent mit sechs
      Schritten, «Bis zum letzten Schritt ändert sich nichts»
- [ ] Schritt Master-Passwort: falsches Passwort → «Falsches Passwort», kein Weiter
- [ ] Schritt Touch ID: Dialog genau einmal
- [ ] **Karte drucken**: Druckdialog ohne Vorschau, Druckerwarnung wie beim Notfallkit, Auftragsname «Dokument»; auf
      dem Blatt QR-Code, daneben die Gruppen zum Abtippen und «Diese Karte ist ein Schlüssel. Getrennt vom Mac
      aufbewahren. Nicht fotografieren.»; «Als PDF sichern» enthält keinen Code
- [ ] Karte ausschneiden und messen: 85,6 × 54 mm (Kreditkartengrösse) → Masse: ______________________
- [ ] Den QR-Code **nicht** mit der Handy-Kamera testen (Live Text und Fotomediathek würden den Schlüssel speichern)
- [ ] Nach dem Drucken wird erst nach einem **Bestätigungs-Scan** geschrieben; Abbruch vorher → Tresor unverändert
- [ ] **Scannen**: Erlaubnis-Dialog beim ersten Mal mit dem Text «Siegel nutzt die Kamera nur, um deine
      QR-Schlüsselkarte zu lesen. Bilder werden nicht gespeichert.»; Vorschau im eigenen Fenster,
      `swift skripte/fenster_pruefen.swift` → auch das Kamerafenster `sharingState 0`
- [ ] Karte etwa 20 cm vor der Kamera wird erkannt; Erkennungszeit notieren: ______ s
- [ ] **Kamera-LED aus nach dem Scan**: Die grüne LED neben der Kamera und der Kamera-Hinweis im Kontrollzentrum
      verschwinden sofort nach dem Erkennen (höchstens ~1 s), ebenso beim Abbrechen, beim Sperren (⌘L) und beim
      Ruhezustand mitten im Scan
- [ ] **Notfallkit in drei Teilen**: drei Blätter «Teil 1 von 3» … «Teil 3 von 3», je mit Kit-Kennung; jedes einzeln
      drucken oder abschreiben; Bestätigung verlangt je Teil eine zufällige Gruppe; falsche Gruppe → nichts geschrieben
- [ ] Zusammenfassung → «Stufe wechseln» → «Stufe Maximal ist aktiv»; Frage «Alte Sicherungen … Entfernen?» →
      «Entfernen»; im Ordner `Sicherungen/<vaultID>/` bleibt nur die neue Sicherung
- [ ] Die drei Teile getrennt ablegen (für den Test genügt: drei beschriftete Blätter)

## A4. Entsperren mit Faktoren (Stufe 4) – früher §10, §11, §3, teilweise

- [ ] Sperrbildschirm zeigt «Zum Öffnen nötig: Passwort – Touch ID – Karte»; Reihenfolge Passwort → Touch ID → Karte
      → «Tresor wird geöffnet …»
- [ ] Falsches Passwort → «Passwort oder ein Faktor stimmt nicht» erst nach allen Faktoren (kein Hinweis, welcher)
- [ ] Falsche Karte (Karte eines zweiten Testtresors oder alte Karte) → «Diese Karte gehört nicht zu diesem Tresor»
      **vor** der Ableitung (keine Wartezeit)
- [ ] Karte abbrechen → «Karte scannen abgebrochen», «Erneut versuchen»
- [ ] «Code von der Karte abtippen» (Kamera abgedeckt) → geht; ein Tippfehler → Meldung «ungültig», kein Absturz
- [ ] Im Kamera-Sheet auf «Code abtippen» umschalten → Kamera-LED und Kamera-Hinweis gehen sofort aus (v4.4);
      «Kamera verwenden» → wieder an
- [ ] Kamera verweigert (Systemeinstellungen → Datenschutz → Kamera → Siegel aus) → verständlicher Hinweis und
      Abtippen als Ausweg; danach wieder erlauben
- [ ] Keine Bilder gespeichert: vorher `touch /tmp/vor-scan`, nach mehreren Scans
      `find ~/Library/Containers/com.aralim.siegel -newer /tmp/vor-scan \( -iname '*.jp*g' -o -iname '*.heic' -o -iname '*.png' -o -iname '*.mov' \)`
      → leer
- [ ] **Kamera-Vorschau extern verdeckt, Erkennung funktioniert** (v4.4, hygiene-4): Fenster auf Sidecar bzw.
      Spiegeln an → Entsperren → im Kamera-Sheet «Vorschau auf diesem Bildschirm verdeckt», Karte vor die Kamera
      halten → wird trotzdem erkannt; «Hier zeigen» zeigt das Bild
- [ ] Gestohlene Datei: `Tresor.siegel` auf einen anderen Mac bzw. in ein anderes Benutzerkonto kopieren → lässt sich
      dort mit Passwort und Karte nicht öffnen (Touch-ID-Schlüssel fehlt), mit zwei Teilen schon (Probe nur dort,
      die Kopie danach löschen)

## A5. Schutz pro Eintrag (SPEC §16) – früher §14, §19, §20, teilweise

- [ ] Neue Einträge in Stufe 4 haben standardmässig Schutz 2; Einstellungen → «Schutz neuer Einträge» lässt 1 nicht zu
- [ ] Schutz 1: Aufdecken/Kopieren in Stufe 4 mit Touch ID (Regel der Stufe), ohne Karte
- [ ] Schutz 2 «Fingerabdruck»: **jedes** Aufdecken, Kopieren, Bearbeiten und der Verlauf verlangen Touch ID
      (zweimal hintereinander aufdecken → zweimal Dialog); Abbrechen → nichts sichtbar
- [ ] Schutz 3 «Hoch»: wie 2, Zwischenablage höchstens 15 s, nie in Autofill
- [ ] Schutz 4 «Maximal»: zusätzlich Karte scannen, bei **jedem** Aufdecken neu; nicht im CSV-/KeePass-Export
- [ ] Liste zeigt bei geschützten Einträgen die Faktor-Symbole; Detail «Geschützt … Aufdecken», danach «Aufgedeckt»
      mit «Verbergen»; Eintrag wechseln → wieder verborgen
- [ ] ⇧⌘C bei einem Eintrag mit Schutz 4 → Touch ID und Karte, dann kopiert
- [ ] Schutz ändern (auch herabsetzen) verlangt zuerst das Aufdecken mit dem bisherigen Schutz
- [ ] Liste, Titel, Benutzernamen und Suche funktionieren ohne Faktoren; Sicherheitsbericht (Seitenleiste
      «Sicherheit») zählt geschützte Einträge mit, ohne sie aufzudecken (kein Touch-ID-Dialog)
- [ ] Nach dem Sperren ist nichts Aufgedecktes mehr sichtbar oder in der Zwischenablage
- [ ] ⌘C im Passwortfeld beim Bearbeiten eines Eintrags mit Schutz 3–5 (Einstellung 90 s): Rückmeldung «… in 15 s
      gelöscht», nach 15 s leer (v4.4, hygiene-3)
- [ ] Bearbeitung, Schutz 5 wählen (kein Sicherheitsschlüssel) → «noch einrichten» → «Jetzt einrichten…» öffnet den
      Assistenten; «Zurück zum Eintrag» bzw. «Fertig» führt in die Bearbeitung mit dem Entwurf zurück (ablaeufe-7)
- [ ] Eintrag mit Schutz 2 bearbeiten, aufdecken, Schutz 5 wählen, ⌘L → Hinweis «mit Schutz 4 statt 5 gespeichert»
      (höchster eingerichteter), kein «Entwurf …», der Eintrag verlangt danach Touch ID und Karte (ablaeufe-1,
      hygiene-1)
- [ ] Eintrag mit Schutz 4 aufdecken, den Touch-ID-Dialog offen lassen, bis die Auto-Sperre greift (Stufe 4: höchstens
      2 Min), dann Finger auflegen → kein Kamera-Sheet über dem Sperrbildschirm, Kamera-Kontrolllicht bleibt aus
      (ablaeufe-4)
- [ ] Mit versiegelten Einträgen: «Neues Notfallkit…» fragt nach dem Bestätigen einmal pro Schutz-Gruppe nach den
      Faktoren (Schutz 2/3: Touch ID; 4: + Karte); Abbrechen → nichts geschrieben, die alten Teile gelten. Danach
      fertigstellen: **ab hier gelten die neuen drei Teile** (alte Blätter vernichten bzw. als ungültig markieren)
- [ ] Einstellungen → «Notfallcode prüfen…» mit zwei neuen Teilen → passt; mit einem alten Teil → abgelehnt
      (Kit-Kennung)

## A6. Selbstvernichtung mit Testtresor (SPEC §23, Stufe 4) – früher §17, §18, §19, §20, teilweise

Nur mit dem **Testtresor** (Stufe 4, Testkarte, Einträge mit erfundenen Daten), nie mit dem echten Tresor. Drei
Testeinträge mit Schutz 4 anlegen: «Test-Vernichtbar A», «Test-Vernichtbar B», «Test-Vernichtbar C». Den Zähler nie
bis zum Ende treiben (das ist C4), sonst sind die markierten Einträge weg.

- [ ] Einstellungen → Sicherheitsstufe → Selbstvernichtung: Warnung «Für vernichtbare Einträge gibt es keinen
      Notfallweg …»; nur Einträge mit Schutz 4/5 zur Auswahl, darunter die Zahl der Einträge mit tieferem Schutz
- [ ] **Ohne Auslöser** (ablaeufe-5): nur «A» markieren, alle Auslöser aus → Hinweis «Ohne Auslöser wird nichts
      vernichtet – die markierten Einträge haben trotzdem keinen Notfallweg» → einschalten (VERNICHTEN, Master-Passwort,
      Touch ID + Karte, **echter Touch-ID-Dialog** für den Vernichtungs-Schlüssel, Freigabe der Notfall-Gruppe mit
      Touch ID + Karte); Zeile in den Einstellungen «Einträge markiert · kein Auslöser»
- [ ] Eingabeprüfungen beim Einschalten: `vernichten` klein → «Tippe VERNICHTEN in Grossbuchstaben …»;
      Vernichtungs-Passwort gleich wie das Master-Passwort → «Das Vernichtungs-Passwort muss sich vom Master-Passwort
      unterscheiden»
- [ ] **Auslöser einschalten mit Sperre mittendrin** (datei-1): «B» dazu markieren, Totmann 30 Tage, Zähler 10,
      Vernichtungs-Passwort neu (zweite Testpassphrase, notieren) → einschalten; während der Rechnung (Stark, einige
      Sekunden) in ein anderes Programm wechseln → Siegel sperrt; nach dem Entsperren ist entweder alles gespeichert
      («B» vernichtbar, Auslöser an) oder nichts (Stand vorher). Bei «nichts» ohne Programmwechsel wiederholen
- [ ] `ls -l@ ~/Library/Containers/com.aralim.siegel/Data/Library/Application\ Support/Siegel/Hardware/`: V, die Ablage
      des Vernichtungs-Passworts (2048 B) und `zustand.json` vorhanden; `tmutil isexcluded <Datei>` → excluded
- [ ] Ältere Sicherungen wurden beim Markieren entfernt (`Sicherungen/<vaultID>/` enthält nur Sicherungen ab jetzt)
- [ ] Markierter Eintrag lässt sich mit Touch ID + Karte aufdecken; «Vernichtbar» im Detail; Bearbeiten bietet keinen
      Schutz unter 4 («Zum Senken zuerst unter Einstellungen → Selbstvernichtung abwählen»)
- [ ] Vernichtbaren Eintrag bearbeiten, Passwort ändern, Schutz 5 wählen (kein Sicherheitsschlüssel), Auto-Sperre →
      Hinweis «mit Schutz 4 statt 5», kein «Entwurf …», Eintrag weiter vernichtbar (hygiene-1)
- [ ] Stufe 4 → 3 mit eingeschalteter Selbstvernichtung: Stufenwahl sagt «Schalte zuerst die Selbstvernichtung aus»
- [ ] **Zähler**: 5 falsche Passwörter (mit richtigen Faktoren) → «Noch 5 Versuche bis zur Vernichtung»; danach mit dem
      Master-Passwort öffnen → Zähler zurückgesetzt, Warnung weg
- [ ] **Zähler auf Sicherungswegen** (datei-5, ablaeufe-6): Siegel beenden, `Tresor.siegel` im Finder aus dem Ordner
      wegbewegen, Siegel starten → «Tresor fehlt»; ein falsches Passwort → «Falsches Passwort für diese Sicherung. Auch
      hier zählt jeder Fehlversuch.»; nach 5 Fehlversuchen «Noch 5 Versuche bis zur Vernichtung». Siegel beenden, Datei
      zurücklegen, starten, mit dem Master-Passwort entsperren → Zähler auf 0
- [ ] VoiceOver: Auswahlzeilen melden «vernichtbar, kein Notfallweg»; Bildschirmaufnahme des Sperrbildschirms mit
      Zähler-Warnung zeigt Siegel nicht (Verdeckung wie sonst)
- [ ] **Vernichtungs-Passwort**: gleiche Dialoge (Touch ID, Karte) und gefühlt gleiche Dauer wie das Master-Passwort;
      «A» und «B» fehlen, kein Hinweis; Einstellungen zeigen die Auslöser, aber keine markierten Einträge;
      «Master-Passwort ändern» scheitert mit «Passwort stimmt nicht»
- [ ] Sperren nach der Vernichtungs-Sitzung: Der Sperrbildschirm sieht aus wie nach einem echten Entsperren (keine
      Warnung, kein Hinweis). Die Frist-Probe (hygiene-5) braucht eine verstellte Uhr und steht in C4
- [ ] Danach mit dem Master-Passwort: Entsperren dauert einmal etwas länger (neuer Tresorschlüssel); Banner «2 Einträge
      wurden vernichtet (Vernichtungs-Passwort, Datum)»; Detail «Vernichtet»; Aufdecken scheitert ohne
      Touch-ID-Dialog; «Entfernen» räumt auf; Selbstvernichtung danach ganz aus
- [ ] Für A7 neu einrichten: «C» markieren, nur den Zähler an (20)

## A7. Notfallweg und Fingerabdruck-Änderung (SPEC §15, §14.1) – früher §13, §18, §10, teilweise

Setzt den Testtresor auf Stufe 1 zurück, darum zum Schluss von Teil A.

- [ ] Einstellungen → «Notfallcode prüfen…» mit Teil 1+2, 1+3 und 2+3 → jedes Mal «Diese Teile passen zu diesem
      Tresor» (ändert nichts)
- [ ] Ein Teil allein bzw. zweimal derselbe Teil → keine Prüfung möglich, verständliche Meldung
- [ ] Tippfehler (1–2 Zeichen) oder `?` in einem Teil → «Stimmen diese Teile?» mit markierten Stellen
- [ ] Ein Teil im Feld für einen einzelnen Code (56 Zeichen) → Siegel wechselt selbst zur Eingabe der Teile
- [ ] Sperren → «Notfallcode verwenden» → nach den Teilen der Hinweis «Für die Selbstvernichtung markierte Einträge
      haben keinen Notfallweg …» (ablaeufe-5) → «Abbrechen» (noch nicht wiederherstellen)
- [ ] Schlüsseldatei fehlt: Siegel beenden, die `<seKeyID>.siegelhw` zum Öffnen aus `Hardware/` auf den Schreibtisch
      verschieben, Siegel starten, entsperren → «Touch ID lässt sich für diesen Tresor nicht verwenden …», nie
      «Falsches Passwort»; Siegel beenden, Datei zurücklegen → öffnet wieder normal
- [ ] **Neuer Finger macht ungültig**: Systemeinstellungen → Touch ID & Passwort → einen Testfinger hinzufügen. Danach
      Siegel entsperren → «Touch ID lässt sich für diesen Tresor nicht verwenden …», «Notfallcode verwenden» als
      Hauptknopf, daneben «Erneut versuchen» als Knopf mit Rahmen (v4.4, bau-1). Nie «Falsches Passwort»
- [ ] «Notfallcode verwenden» → Teil 2 + Teil 3 → neues Master-Passwort → «Tresor wiederhergestellt»: Eintragszahl,
      letzte Änderung, «Sicherheitsstufe und Schutz aller Einträge sind jetzt wieder 1»; «Test-Vernichtbar C» fehlt;
      Selbstvernichtung aus; alle anderen Einträge lesbar, auch die früher mit Schutz 4
- [ ] Die alte Datei liegt als angeheftete Sicherung «vor-notfall» in `Sicherungen/`
- [ ] Einstellungen → «Sicherung einspielen…»: Panel öffnet im Ordner «Sicherungen»; eine Sicherung von vor der
      Wiederherstellung (Stufe 4) wählen → Touch ID nicht nutzbar → «Notfallcode verwenden» öffnet genau diese Datei
      (datei-3) → danach wieder Stufe 1
- [ ] `Tresor.siegel` im Finder wegbewegen → «Tresor fehlt» → «Passwort vergessen? Notfallcode verwenden» → zwei Teile
      → «Sicherung vom …»; «Zurück» führt wieder zu «Tresor fehlt» (datei-2)
- [ ] Den Testfinger in den Systemeinstellungen wieder entfernen

---

# Teil B – danach, mit dem Testtresor

## B1. Bildschirmaufnahme: alle Fenster `sharingState 0` (SPEC §6, §10) – früher §1

Werkzeug: `swift skripte/fenster_pruefen.swift` listet alle Fenster des Siegel-Prozesses mit
`kCGWindowSharingState` (0 = none, geschützt; 1 = readOnly, aufnehmbar).

- [ ] Hauptfenster entsperrt, Detailansicht offen: `swift skripte/fenster_pruefen.swift` → «Ergebnis: ok»
- [ ] Beobachten starten: `swift skripte/fenster_pruefen.swift --beobachten`, dann nacheinander öffnen und
      wieder schliessen, am Schluss ctrl-C → «Ergebnis: ok», nie eine Zeile «OFFEN»:
  - [ ] Einstellungen (⌘,)
  - [ ] Bearbeiten (⌘E) mit Generator
  - [ ] Notfallkit (Code-Anzeige und Bestätigung der zwei Gruppen)
  - [ ] Bestätigungen: Löschen, «Verlauf leeren», «Bisherige Sicherungen entfernen?»
  - [ ] Master-Passwort erneut abfragen (heikle Aktion, z. B. CSV exportieren…)
  - [ ] CSV-Import-Vorschau
  - [ ] Fehlermeldung (Alert), z. B. CSV mit falschem Format einlesen
  - [ ] Druckdialog des Notfallkits
  - [ ] **Sheets ohne Klick**: Meldungen, die nach einer Hintergrundarbeit erscheinen (nach Argon2:
        «Trotzdem öffnen?», Wiederherstellung über den Notfallcode, Passwortwechsel). Gemessen mit einer
        Test-App: Ein Sheet, das ohne Benutzereingabe erscheint, war mit einer WindowGuard nur über
        `NSApplication.didUpdateNotification` **mehrere hundert Millisekunden sichtbar und aufnehmbar**
        (`OFFEN`); mit zusätzlichem Beobachter auf `NSWindow.willBeginSheetNotification` nie.
- [ ] Gegenprobe, dass das Werkzeug Offenes erkennt: `swift skripte/fenster_pruefen.swift $(pgrep -x Finder)`
      → «Ergebnis: FEHLER»
- [ ] Sichtprobe: ⌘⇧5 → «Ganzen Bildschirm aufnehmen» (Bildschirmfoto und Video) mit offenem Sheet: Siegel und
      das Sheet fehlen oder sind leer (sonst Befund notieren)
- [ ] Fenstertitel ist überall «Siegel» (Fenster-Menü, Mission Control, ⌘-Tab)

Hinweise:
- Unter macOS 26 besitzt jede App unsichtbare **Menüleisten-Streifen** (bildschirmbreit, so hoch wie die
  Menüleiste, oben am Bildschirm, `sharingState 1`; Finder hat sie auch). Sie stehen nicht in
  `NSApp.windows`, die WindowGuard erreicht sie nicht, und sie enthalten nur die Menütitel.
  `fenster_pruefen.swift` zeigt sie als «Menüleiste (System)» und wertet sie nicht.
- Öffnen- und Sichern-Dialoge laufen in der Sandbox in einem eigenen Systemprozess und erscheinen nicht unter
  der PID von Siegel. Sie zeigen nur Dateinamen.

## B2. Zwischenablage und Zwischenablageverlauf (SPEC §6 SecretPasteboard) – früher §2

Typen der Zwischenablage anzeigen (liest nur die Typen, nicht den Inhalt):
`echo 'import AppKit; print(NSPasteboard.general.types?.map(\.rawValue) ?? [])' | swift -`

- [ ] Passwort über den Kopieren-Knopf kopieren → Zeile «Kopiert – wird in 30 s gelöscht»; die Typen enthalten
      `org.nspasteboard.ConcealedType` und `org.nspasteboard.TransientType`
- [ ] **⌘C** im Passwortfeld beim Bearbeiten, in den Notizen, im Generator-Ergebnis und im Verlauf sowie
      Kontextmenü «Kopieren»: jeweils dieselben zwei Typen
- [ ] **Zwischenablageverlauf** (Spotlight, ⌘-Leertaste, Ansicht «Zwischenablage»): Keiner der kopierten
      Werte erscheint dort. Falls ein Zwischenablage-Programm installiert ist (Raycast, Paste, Maccy …),
      dort ebenfalls nichts. Ergebnis auch in `SICHERHEIT.md` §7 nachtragen
- [ ] Nach Ablauf der Frist (Einstellung 15/30/60/90 s) ist die Zwischenablage leer
- [ ] Sperren (⌘L) und Beenden leeren die Zwischenablage sofort; die Sperre beim App-Wechsel (Stufe 3–5) nicht – dort
      läuft die Frist weiter (v4.4, siehe A2)
- [ ] Wurde danach in einer anderen App etwas kopiert, lässt Siegel es stehen (nur bei unverändertem
      `changeCount` leeren)
- [ ] Nach einem Absturz (Testtresor: `kill -9 $(pgrep -x Siegel)` direkt nach dem Kopieren) leert der
      nächste Start die Zwischenablage
- [ ] **Universal Clipboard**: iPhone/iPad mit derselben Apple-ID und Handoff an. Nach dem Kopieren in Siegel
      fügt das Gerät nichts ein (`currentHostOnly`)
- [ ] Master-Passwort aus der Zwischenablage ins Sperrfeld einfügen und entsperren → Meldung «Zwischenablage
      geleert – sie enthielt dein Master-Passwort», die Zwischenablage ist leer

## B3. Externe Bildschirme und Sidecar (SPEC §6) – früher §3

- [ ] Fenster auf das iPad (**Sidecar**) ziehen: sichtbares Passwort (Auge) und Notfallcode werden verdeckt
      (Platzhalter); zurück auf dem eingebauten Bildschirm wieder sichtbar
- [ ] Dasselbe auf einem Monitor bzw. AirPlay-Bildschirm als **erweiterter** Schreibtisch
- [ ] Einstellung «Geheimnisse auf externen Bildschirmen zeigen» (Standard aus): an → sichtbar, aus → verdeckt
- [ ] **Bildschirm spiegeln** (AirPlay-Synchronisierung, Beamer, «Eingebauten Bildschirm spiegeln»): sichtbares
      Passwort, Generator-Ergebnis und Notfallcode sind **verdeckt** (Platzhalter «Auf diesem Bildschirm verdeckt»),
      obwohl der eingebaute Bildschirm das Spiegel-Set vertritt (`CGDisplayIsInMirrorSet`); Spiegeln aus →
      wieder sichtbar. Ergebnis auch in `SICHERHEIT.md` §7 und §13 nachtragen
- [ ] Ohne «Bildschirme verwenden verschiedene Spaces» (Systemeinstellungen → Schreibtisch & Dock): Fenster so
      verschieben, dass es zu einem kleinen Teil auf dem iPad bzw. Monitor liegt → verdeckt, sobald es den
      externen Bildschirm schneidet
- [ ] Notfallkit-Anzeige und Karte im Assistenten auf Sidecar → verdeckt (Kamera-Vorschau: siehe A4)

## B4. Diktat, Dienste-Menü, Textersatz, Writing Tools (SPEC §6) – früher §4

- [ ] Menü «Bearbeiten»: kein «Diktat starten…», kein «Emoji & Symbole», keine AutoFill-Einträge
- [ ] Rechtsklick in Geheimnis-Feldern (Passwort beim Bearbeiten, Notizen, Verlauf, Notfallcode-Eingabe,
      Generator-Ergebnis): nur «Kopieren» (beim Bearbeiten dazu «Einfügen», «Alles auswählen»). Kein
      «Dienste», «Nachschlagen», «Übersetzen», «Sprachausgabe», keine Writing Tools
- [ ] Menü «Siegel» → «Dienste» mit Fokus in einem Geheimnis-Feld: keine Dienste angeboten
- [ ] Diktat-Kurzbefehl (Globus-/Mikrofontaste) im Notizfeld: Befund notieren (die SPEC verlangt nur das
      Entfernen des Menüeintrags): ______________________
- [ ] Textersatz (Systemeinstellungen → Tastatur → Textersetzung, z. B. «mfg»): in keinem Siegel-Feld ersetzt;
      keine Autokorrektur, keine rote Unterstreichung, keine grauen Wortvorschläge, keine automatischen
      Anführungszeichen/Gedankenstriche, keine Link-Erkennung
- [ ] Writing Tools (Apple Intelligence): in keinem Feld angeboten
- [ ] Secure Event Input: Mit Fokus im Master-Passwortfeld und in der Notfallcode-Eingabe zeigt
      `ioreg -l -w 0 | grep kCGSSessionSecureInputPID` die PID von Siegel; nach Fokuswechsel, Sperren und
      Beenden nicht mehr
- [ ] Geheimnisse lassen sich nicht herausziehen (Drag & Drop) und Anzeige-Texte nicht markieren

## B5. Bedienungshilfen (SPEC §6) – früher §5

Nicht nur der Wert zählt: Jedes Programm mit Bedienungshilfen-Recht kann auch die parametrisierten
Text-Attribute abfragen (`AXStringForRange`, `AXAttributedStringForRange`, `AXRTFForRange`) sowie
`AXSelectedText` und `AXNumberOfCharacters`. Werkzeug: `swift skripte/ax_pruefen.swift --suche <Testgeheimnis>`
fragt all das für jedes Element des laufenden Siegel ab (das Terminal braucht das Recht «Bedienungshilfen»).

- [ ] Testeintrag mit Passwort `AXPROBE-4711`, Notiz `AXNOTIZ-4711`; Passwort aufgedeckt (Auge), Verlauf
      aufgeklappt und aufgedeckt: `swift skripte/ax_pruefen.swift --suche AXPROBE --suche AXNOTIZ` → «Ergebnis: ok»
- [ ] Dasselbe beim **Bearbeiten** (Passwortfeld mit und ohne Fokus, Notizen mit Fokus, Generator offen) → ok
- [ ] Dasselbe mit einem Eintrag mit Schutz 2, aufgedeckt → ok
- [ ] Sperrbildschirm → «Notfallcode verwenden», Testcode eintippen: `--suche` mit der ersten Gruppe → ok
- [ ] Gegenprobe: `--suche` mit dem Titel des Eintrags → «FEHLER» (Klartext-Felder sind absichtlich lesbar)
- [ ] Accessibility Inspector (Xcode → Open Developer Tool) über der Passwortzeile: kein Wert, Bezeichnung
      «Passwort, verborgen»; über der Notfallcode-Eingabe «Notfallcode, verborgen»
- [ ] VoiceOver an (⌘F5): Wert wird vorgelesen und die Felder lassen sich bedienen; VoiceOver aus: wieder
      verborgen (Siegel nach dem Umschalten neu öffnen, damit auch die SwiftUI-Hüllen neu gebaut werden)

## B6. Drucken und Druckerwarnung (SPEC §7.6, §14.2) – früher §6

Geräte-URIs der Drucker: `lpstat -v`. Was schon in A1/A3 geprüft wurde, nur abhaken, wenn es dort gelang.

- [ ] Drucker mit `ipp://`, `http://`, `socket://`, `lpd://`, `smb://` oder `dnssd://…` mit Dienst
      `_ipp` (ohne s), `_printer`, `_pdl-datastream` → Warnung «Dieser Drucker empfängt unverschlüsselt über
      das Netzwerk; Firmendrucker speichern Aufträge oft» mit «Trotzdem drucken»
- [ ] Drucker mit `ipps://` oder USB → keine Warnung
- [ ] Standarddrucker ist USB, **im Druckdialog** einen `ipp://`-Drucker wählen → die Warnung erscheint danach
      trotzdem (geprüft wird der gewählte Drucker); «Trotzdem drucken» druckt ohne zweiten Dialog
- [ ] Drucker ohne lesbare Geräte-URI → Warnung «Siegel kann nicht prüfen, wie dieser Drucker angebunden ist»
- [ ] Druckdialog ohne Vorschau; Auftragsname in der Warteliste «Dokument» (Drucker vorher anhalten,
      `lpstat -o` zeigt den Auftrag; danach löschen)
- [ ] Im Druckdialog «PDF ▾» → «Als PDF sichern…», «In Vorschau öffnen» und «In iCloud Drive sichern»: Das Ergebnis
      enthält **keine Codegruppe**, sondern «Notfallkit nur auf Papier – Code nicht enthalten»; Siegel zeigt den
      Hinweis «Als PDF … gibt Siegel den Code nicht aus» und nicht «Gedruckt». Dasselbe für Karte und Teile
- [ ] Nach dem Druck: Bestätigung über zwei zufällige Gruppen; kein Kopieren, kein PDF-Knopf in Siegel
- [ ] Warteliste nach dem Druck leer (Systemeinstellungen → Drucker & Scanner → Warteliste)

## B7. Sicherungen in der signierten Sandbox-App (SPEC §4) – früher §6a

Die Tests laufen ohne Sandbox und sehen Sandbox-Grenzen nicht. Darum in `~/Applications/Siegel.app`:

- [ ] «Sicherung exportieren…» auf den Schreibtisch, auf einen USB-Stick (exFAT) und nach iCloud Drive: klappt,
      im Zielordner entsteht nur die gewählte Datei (keine `.….tmp`); danach verschwindet die Zeile «Keine
      Sicherung ausserhalb dieses Macs»
- [ ] Nach dem Export auf den USB-Stick steht «Liegt ausserhalb dieses Macs»; nach dem Export in ein eingehängtes
      DMG **nicht** (DiskArbitration in der Sandbox)
- [ ] Dasselbe Ziel nochmals wählen und ersetzen → klappt
- [ ] Zweiter Sicherungsort auf einem USB-Stick; Siegel beenden, Stick ausstecken, Siegel starten und etwas
      ändern → Seitenleiste «Zweiter Sicherungsort nicht verbunden», Einstellungen zeigen den Namen mit «Nicht
      verbunden» und «Entfernen»; Stick einstecken → Zeile verschwindet nach dem nächsten Speichern, am Stick
      entsteht eine neue Kopie
- [ ] Master-Passwort ändern mit ausgestecktem Stick → «Entfernen» meldet, dass die Kopien am Stick noch da sind;
      Stick einstecken → «Alte Sicherungen am zweiten Ort entfernt», am Stick nur noch eine neue Kopie
- [ ] `Tresor.siegel` und `Sicherungen/` im Container wegbewegen (Testtresor!), Stick eingesteckt, Siegel starten →
      «Tresor fehlt» mit den Sicherungen vom Stick (Kennzeichnung «extern»), nicht die Einrichtung; danach
      zurücklegen
- [ ] Zweiter Sicherungsort in iCloud Drive mit ausgelagerten Dateien, `Tresor.siegel` wegbewegen, Siegel starten →
      das Fenster bleibt bedienbar, «Sicherungen werden gesucht…», danach die Liste (ablaeufe-10)
- [ ] Stufe-2-Sicherung exportieren: Der Text sagt, dass sie Touch ID dieses Macs braucht und auf einem anderen Mac
      nur der Notfallcode öffnet (design-3)

## B8. Sperren und Beenden (SPEC §6) – früher §7

- [ ] Auto-Sperre (1 Min einstellen): ohne Eingabe in Siegel nach 1 Min gesperrt, auch wenn Siegel im
      Hintergrund war (Prüfung beim Aktivieren, bevor Inhalt sichtbar wird)
- [ ] Ruhezustand, Bildschirm sperren (⌃⌘Q), Benutzerwechsel → beim Zurückkommen gesperrt, kein Inhalt blitzt auf
- [ ] Ohne offenen Tresor: Notfallcode eingetippt und bestätigt (Schritt «Neues Master-Passwort») bzw. Passwort im
      Sperrfeld stehen gelassen → nach der Auto-Sperre-Frist, Ruhezustand oder ⌃⌘Q ist alles geleert
- [ ] Enter im Sperrfeld und sofort ⌃⌘Q → nach dem Zurückkommen gesperrt (der Tresor öffnet sich nicht hinter
      der Bildschirmsperre)
- [ ] Master-Passwort ändern (Profil «Stark») und während der Fortschrittslinie ⌘Q → Siegel wartet bis zu 5 s;
      bzw. ⌘L → nach dem nächsten Entsperren erscheint die Frage «Bisherige Sicherungen … Entfernen?»
- [ ] Offene Bearbeitung (Schutz 1) beim Sperren → gespeichert (bzw. als «Entwurf <Datum>» mit Hinweis)
- [ ] ⌘Q mit offenem Sheet: Gemessen mit der Test-App lehnt AppKit das Beenden bei angehängtem Sheet ab
      (Apple-Event quit → Fehler -128), ohne `applicationShouldTerminate` zu fragen. Verhalten von Siegel
      notieren: ______________________; `./build.sh` bricht in diesem Fall mit einer Meldung ab (kein kill)
- [ ] CSV exportieren, Exportdatei liegen lassen, Fenster schliessen bzw. ⌘Q → Siegel fragt nach der liegenden
      CSV-Datei (auch nach dem Schliessen des Fensters)
- [ ] Einzelinstanz: `open -n ~/Applications/Siegel.app` → «Siegel läuft bereits», die zweite Instanz endet

## B9. Prozess und Sandbox (SPEC §5, §6) – früher §8

- [ ] Aktivitätsanzeige, Spalte «Sandbox»: Siegel = Ja
- [ ] Kein Netzwerk: `lsof -i -a -p $(pgrep -x Siegel)` bleibt leer
- [ ] Debugger gesperrt: `lldb -p $(pgrep -x Siegel)` → Anhängen scheitert
- [ ] Unified Log ohne Inhalte: `/usr/bin/log stream --level debug --predicate 'process == "Siegel"'` (in zsh
      ist `log` ein eingebauter Befehl, darum der volle Pfad) während Entsperren, Kopieren, Bearbeiten, Import,
      Aufdecken mit Faktoren → keine Titel, Benutzernamen, Passwörter, Notizen, Codes
- [ ] Keine Fenster-Wiederherstellung: Siegel mit offenem Eintrag beenden und neu starten → Sperrbildschirm,
      kein wiederhergestellter Zustand
- [ ] FileVault-Hinweis erscheint nur bei ausgeschaltetem FileVault (Einrichtung und «Sicherheit»)
- [ ] Kamera und USB nur bei Bedarf: Ohne Scan zeigt das Kontrollzentrum keinen Kamera-Hinweis; ohne Vorgang mit
      dem Sicherheitsschlüssel zeigt `ioreg -l -w 0 | grep IOUserClientCreator | grep Siegel` keine offene
      Verbindung (Ergebnis notieren): ______________________

## B10. Icon, Tastatur, Lizenzanzeige – früher §9, ergänzt

- [ ] Finder, Dock, ⌘-Tab: weisser Squircle mit schwarzem S, kein grauer Rahmen; auch im dunklen
      Erscheinungsbild und klein in der Finder-Listenansicht
- [ ] Tastatur im echten Fenster: ↑ ↓ in der Liste, Enter bearbeitet, Esc bricht ab bzw. leert die Suche; ⌘F, ⌘N,
      ⌘E, ⌘S, ⇧⌘C, ⌘L, ⌘, wirken wie in `LIESMICH.md` beschrieben
- [ ] Einstellungen → Info → «Lizenzen…»: libsodium mit «Copyright (c) 2013-2026 Frank Denis» und ganzem ISC-Text,
      zxcvbn mit beiden Copyright-Zeilen und ganzem MIT-Text, Hinweis auf die Rohdaten der Wortlisten
      (`LIZENZEN.md`, Pflichten)

---

# Teil C – mit zusätzlicher Hardware, Konto oder Programm

## C1. Sicherheitsschlüssel FIDO2 (SPEC §14.3, Stufe 5, Schutz 5) – früher §12

Bis dieser Abschnitt einmal ganz abgehakt ist, trägt der FIDO2-Code den Hinweis «mit echter Hardware ungetestet»
(SPEC §13). Gerät notieren (Hersteller, Modell, Firmware): ______________________

- [ ] Schlüssel einstecken → Siegel zeigt ihn (Hersteller/Produkt); ohne Schlüssel lässt sich Stufe 5 wählen, das
      Einrichten verlangt aber einen
- [ ] **Registrieren**: Berührung verlangt (LED blinkt), 30 s Frist; ohne Berührung → Abbruch mit Meldung, nichts
      geschrieben
- [ ] **Entsperren** mit Passwort + Touch ID + Karte + Berührung → offen; Schlüssel abgezogen → Meldung, kein
      Absturz; anderer Schlüssel desselben Modells bzw. zurückgesetzter Schlüssel → «Das ist nicht der
      Sicherheitsschlüssel dieses Tresors, oder er wurde zurückgesetzt …» (v4.4), kein Hinweis auf eine PIN
- [ ] Schlüssel mit gesetzter PIN: hmac-secret ohne PIN klappt; verlangt das Gerät Benutzerprüfung (UV) →
      Hinweis «Faktor nicht verfügbar» mit Erklärung
- [ ] Während einer Anfrage abziehen und wieder einstecken → sauberer Fehler, nächster Versuch klappt
- [ ] **Abbrechen beendet den Vorgang** (v4.4): Schlüssel blinkt → «Abbrechen» (bzw. ⌘L) → LED hört sofort auf zu
      blinken, `ioreg -l -w 0 | grep IOUserClientCreator | grep Siegel` zeigt höchstens ~1 s danach keine offene
      Verbindung; gleich danach erneut → **eine** Berührung genügt
- [ ] Schlüssel gleichzeitig im Browser in Gebrauch (z. B. WebAuthn-Dialog offen) → «Der Sicherheitsschlüssel ist
      gerade mit einem anderen Vorgang beschäftigt …», kein PIN-Hinweis
- [ ] Schutz 5 «Festung»: zusätzlich Sicherheitsschlüssel berühren, bei jedem Aufdecken neu
- [ ] Stufe 5 mit einem schon für Einträge eingerichteten Sicherheitsschlüssel: der Assistent verlangt denselben
      Schlüssel zu berühren (keine Neuregistrierung); Einträge mit Schutz 5 bleiben danach aufdeckbar
- [ ] Mit versiegelten Einträgen mit Schutz 5: «Neues Notfallkit…» fragt einmal Touch ID + Karte + Schlüssel für die
      Schutz-5-Gruppe
- [ ] Danach: `SecurityKeyFactor.testedWithHardware = true` in
      `Sources/SiegelHardware/FIDO2/SecurityKeyFactor.swift`; den Hinweis «mit echter Hardware ungetestet» in
      `SICHERHEIT.md` §9, `README.md` und `LIESMICH.md` anpassen; Gerät und Datum in `SPEC.md` §12 vermerken

## C2. Autofill mit bezahltem Entwicklerkonto (SPEC §20, Erweiterungen/LIESMICH.md) – früher §15

Geht nur mit einem bezahlten Apple-Entwicklerkonto; mit dem kostenlosen Team scheitert schon die Signatur (gemessen).

- [ ] `SIEGEL_TEAM_ID=… skripte/autofill_bauen.sh` → «signiert, Entitlements wie erwartet», ohne `get-task-allow`
- [ ] Umzug des Tresors in den Gruppen-Container
      (`~/Library/Group Containers/<TEAM-ID>.com.aralim.siegel/Library/Application Support/Siegel/`): Tresor,
      Sicherungen, Hardware-Blobs da, alter Ordner als `Siegel-vor-Umzug` erhalten, Tresor öffnet sich mit Passwort
      (+ Touch ID)
- [ ] Systemeinstellungen → Allgemein → AutoFill & Passwörter: «Siegel» erscheint und lässt sich einschalten
- [ ] Safari, Anmeldeseite einer Test-Website → «Passwörter…» → Siegel: Master-Passwort (bei Stufe 2/3 zusätzlich
      Touch ID), danach nur passende Einträge; Auswahl setzt Benutzer und Passwort ein
- [ ] Phishing-Probe: Eintrag für `https://beispiel-bank.example`, Seite `beispiel-bank.example.evil.com` bzw.
      Punycode-Doppelgänger → **kein** Treffer; `http://`-Seite für einen `https://`-Eintrag → kein Treffer
- [ ] Eintrag mit Schutz 2 → Touch ID bei der Auswahl; Schutz 3–5 erscheinen nie
- [ ] Tresor-Stufe 4/5 → Hinweis «… nur in der App», ohne nach dem Passwort zu fragen
- [ ] Nie still ausfüllen: keine Siegel-Vorschläge in der QuickType-Leiste, kein Ausfüllen ohne Bedienung
- [ ] Nach Auswahl oder Abbruch ist der Tresor in der Erweiterung gesperrt; 2 Min ohne Auswahl → Abbruch
- [ ] Zwischenablage (v4.4, bau-2): Master-Passwort aus einer Notiz kopieren und per ⌘V bzw. Kontextmenü «Einfügen»
      eingeben → nach dem Entsperren steht «Zwischenablage geleert – sie enthielt dein Master-Passwort.»; nach
      Auswahl oder Abbruch ist die Zwischenablage leer. Nach dem Einfügen etwas anderes kopiert → bleibt unangetastet.
      Getippt statt eingefügt → Zwischenablage unberührt. Kommt ⌘V im System-Fenster an? ______________________
- [ ] Touch ID vorübergehend weg (v4.4, bau-1): fünfmal falscher Finger bzw. Deckel zu → Meldung «… gesperrt …» bzw.
      «… nicht erreichbar …» ohne Notfallweg; das Passwortfeld (beim Entsperren) bzw. die Liste (beim Eintrag) bleibt,
      erneut versuchen geht – nicht nur «Schliessen»
- [ ] Touch ID beim Eintrag (Schutz 2) abbrechen → Liste bleibt, darüber «Touch ID abgebrochen.» (v4.4, bau-3)
- [ ] Speicher: Entsperren mit Profil «Stark» (2 GiB) klappt in der Erweiterung (keine Meldung «Nicht genug freier
      Arbeitsspeicher», kein Abbruch durch das System)
- [ ] `swift skripte/fenster_pruefen.swift $(pgrep -x SiegelAutofill)` während die Erweiterung offen ist → Ergebnis
      notieren (die Ansicht wird vom System gehostet): ______________________
- [ ] Secure-Enclave-Blob aus der App funktioniert in der Erweiterung (Stufe 2/3)
- [ ] Rückweg zur ad-hoc-App aus `./build.sh` mit Rückumzug des Tresors geprüft

## C3. KeePass-Export gegen echte Programme (SPEC §19) – früher §16

Formal geprüft ist der Export nur mit dem eigenen Test-Leser und der Python-Referenz (`referenz/gegenprobe.sh`,
`ReferenzTests`). KeePassXC und KeePass 2 sind hier nicht installiert.

- [ ] Testtresor (Stufe 1–3) mit Sonderzeichen, Zeilenumbrüchen in Notizen, einem 2FA-Geheimnis und einem Eintrag mit
      Schutz 2 → «KeePass exportieren…» (Touch ID für den geschützten Eintrag)
- [ ] Export-Passwort zu schwach bzw. gleich dem Master-Passwort → abgelehnt
- [ ] Datei in **KeePassXC** öffnen: Export-Passwort öffnet, alle Felder byte-genau, der 2FA-Code in KeePassXC ist
      derselbe wie in Siegel, Gruppe «Siegel», keine früheren Passwörter, keine Einträge mit Schutz 4/5
- [ ] Dasselbe in **KeePass 2** (oder Strongbox), falls vorhanden
- [ ] Falsches Export-Passwort → KeePassXC lehnt ab; Exportordner `Siegel-Export-<Datum>.noindex` danach löschen
      («Exportdatei löschen» in Siegel)

## C4. Zweites macOS-Benutzerkonto oder VM – früher §8, §17, §18, §19, teilweise

Für alles, was die Systemuhr, einen zweiten Mac oder eine veränderte App braucht. Die Systemuhr gilt für den ganzen
Mac: Uhr-Proben nur in einer VM oder kurz und mit Bedacht.

- [ ] **Signatur-Selbstprüfung** (§21) mit Testtresor: `SIEGEL_INSTALL_DIR=… ./build.sh`, in der Kopie eine Datei in
      `Contents/Resources` ändern → `codesign --verify --strict` scheitert, Siegel startet mit «Siegel ist
      beschädigt» und entsperrt nicht; die unveränderte App entsperrt normal. Ehrlich (v4.4): Eine veränderte Datei in
      `Resources` löst die Meldung aus; ein verändertes Programm (`Contents/MacOS/Siegel`) beendet macOS mit Hardened
      Runtime schon vorher, die Meldung erscheint dann nicht
- [ ] **Neuer Mac** (datei-2/-3): Sicherung einer Stufe-2-Tresordatei auf einen Stick, im zweiten Konto in der
      Einrichtung «Aus Sicherung wiederherstellen…» → Touch ID nicht verwendbar → «Notfallcode verwenden» → Code →
      Tresor in Stufe 1
- [ ] **Totmann**: Frist 7 Tage, Uhr um 8 Tage vorstellen, Siegel aktivieren oder 10 Minuten warten → vernichtet, auch
      gesperrt; Aufwachen aus dem Ruhezustand löst die Prüfung ebenfalls aus; beim nächsten echten Entsperren Banner
      «Totmann-Schalter»
- [ ] **Totmann-Frist** (hygiene-5): Frist 30 Tage, letzte echte Entsperrung vor 25 Tagen (Uhr vorstellen):
      Sperrbildschirm zeigt «Frist endet am …»; mit dem Vernichtungs-Passwort öffnen, sperren → die Frist ist weg (wie
      nach dem Master-Passwort); auch nach einem Neustart von Siegel
- [ ] **Uhr zurück**: Uhr um mehr als einen Tag zurückstellen → nichts vernichtet, Frist nicht verlängert
- [ ] **Zähler bis zum Ende**: 10 falsche Passwörter → vernichtet (beim nächsten echten Entsperren Banner
      «Fehlversuch-Zähler»)
- [ ] **Fast volle Platte** (nur in einer VM): ⌘L mit offener Bearbeitung bei unter 64 MiB freiem Platz → Meldung,
      nichts verloren, alte Datei unverändert

---

# Z. Abschluss: Testdaten wegräumen

Löschen macht Aralim selbst (Finder oder Papierkorb); vorher kontrollieren, dass nur Testdaten betroffen sind.

- [ ] Siegel beenden (⌘Q)
- [ ] Inhalt von `~/Library/Containers/com.aralim.siegel/Data/Library/Application Support/Siegel/` ansehen: nur
      `Tresor.siegel`, `Sicherungen/`, `Hardware/` und `.lock` des Testtresors
- [ ] Diese Dateien **von Aralim** in den Papierkorb legen lassen (Testtresor, Sicherungen, Schlüsseldateien;
      `.lock` darf bleiben); Exporte vom Schreibtisch, USB-Stick und iCloud Drive ebenso
- [ ] Testkarte, Testblätter und Teile vernichten (zerschneiden), auch wenn sie nur zum Testtresor gehören
- [ ] Testfinger in den Systemeinstellungen entfernt (A7)
- [ ] Ergebnisse oben in die Tabelle eintragen; Befunde in `SPEC.md` §12 bzw. als Aufgabe festhalten
