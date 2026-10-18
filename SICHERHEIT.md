# Siegel – Sicherheit

Stand 17.10.2026, SPEC v4.5, Dateiformat Version 2 (Version 1 bleibt lesbar). Die technischen Einzelheiten stehen in
`SPEC.md`. Hier steht in Alltagssprache, was Siegel schützt, wie es das tut und wo die Grenzen liegen. Neu seit v4:
Sicherheitsstufen und Faktoren (Abschnitte 8 und 9), Schutz pro Eintrag (10), Selbstvernichtung (11, seit v4.3) und
die Aussperr-Risiken mit den Wegen zurück (12).

Vorweg, ehrlich: Siegel ist ein Einzelprojekt, mit KI-Agenten (Claude Code) gebaut und von KI-Agenten in mehreren
Runden geprüft. Die Verschlüsselung stammt aus erprobten Bibliotheken (libsodium und Apples CryptoKit), nichts davon
ist selbst erfunden. Wie diese Bausteine zusammengesetzt sind (Dateiformat, Notfallschlüssel, Faktoren,
Eintrags-Schutz, Selbstvernichtung), hat aber noch kein Mensch unabhängig geprüft. Touch ID, Kamera und
Sicherheitsschlüssel sind mit echter Hardware noch nicht durchgeprüft (`PRUEFLISTE.md`, Teil A und C). Viele
automatische Tests ersetzen kein Audit.

## Das Wichtigste in zehn Punkten

1. **Passphrase vorschlagen lassen** (6 Wörter) statt ein eigenes Passwort ausdenken.
2. **Notfallkit nur auf Papier**, nie fotografieren, getrennt vom Mac aufbewahren. Bei drei Teilen: an drei
   verschiedenen Orten.
3. **FileVault einschalten**, falls es aus ist (Abschnitt 13).
4. **«Mac-Analysedaten teilen» ausschalten**, damit Absturzberichte nicht an Apple gehen.
5. **Siegel sperren (⌘L), bevor** jemand per Fernwartung, Bildschirmfreigabe oder KI-Steuerung an den Mac
   kommt oder bevor du den Bildschirm spiegelst (Beamer, AirPlay).
6. **Einen zweiten Sicherungsort wählen** (z. B. USB-Stick). Die Sicherungen liegen sonst nur auf diesem Mac.
7. **CSV-Dateien** mit Passwörtern nur kurz behalten und danach endgültig löschen.
8. **Nach einem Verdacht** nicht nur das Master-Passwort wechseln, sondern auch die wichtigen Passwörter im
   Tresor (Abschnitt 7, «Alte Kopien»).
9. **Ab Stufe 2 ist das Notfallkit der Weg auf einen neuen Mac.** Touch ID gilt nur auf diesem Mac; eine Sicherung
   allein öffnet dort nichts (Abschnitt 12).
10. **Fingerabdrücke nicht ändern, ohne das Notfallkit bereitzulegen.** Ein neuer oder gelöschter Finger macht die
   Touch-ID-Schlüssel unbrauchbar, vernichtbare Einträge gehen dabei verloren (Abschnitt 12).

## 1. Wogegen Siegel schützt

- **Die Datei wird gestohlen.** Aus einem Backup, einer Cloud, von einem USB-Stick oder mit dem ganzen Laptop.
  Wer nur die Datei hat, muss dein Master-Passwort erraten. Das ist absichtlich sehr teuer (Abschnitt 4), auch
  für jemanden, der die Datei heute speichert und in Jahrzehnten einen Quantenrechner hat. **Ab Stufe 2** reicht
  Raten allein nicht: Der Touch-ID-Faktor liegt nur in der Secure Enclave dieses Macs, nicht in der Datei.
- **Die Datei wird verändert.** Jede Änderung, auch ein einzelnes gekipptes Bit, fällt auf: Siegel öffnet die
  Datei dann nicht, statt falschen Inhalt zu zeigen. Wer eine ältere Version zurückspielt, löst eine Warnung
  aus («Trotzdem öffnen?»).
  Einschränkung beim Notfallweg: Er schützt die Vertraulichkeit, nicht die Herkunft. Wer eine alte Kopie deiner
  Datei hat, könnte eine gefälschte Datei bauen, die sich mit deinem echten Notfallcode öffnen lässt, etwa mit
  einer falschen Bank-Adresse darin. Darum zeigt Siegel nach einer Wiederherstellung die Zahl der Einträge und
  die letzte Änderung: Inhalt prüfen. Der normale Weg mit dem Master-Passwort ist voll abgesichert.
- **Neugierige Blicke im Alltag.** Bildschirmaufnahmen, Blick über die Schulter, Zwischenablage,
  Autokorrektur und Schreibwerkzeuge, Dienste-Menü, Bedienungshilfen, Fenster-Wiederherstellung,
  Absturzberichte, Protokolle, CSV-Dateien, Druckaufträge. Siegel schliesst hier so viel wie möglich ab;
  die Lücken stehen in Abschnitt 7.
- **Die vergessene Sitzung.** Siegel sperrt sich nach 5 Minuten ohne Eingabe (einstellbar 1–30, ab Stufe 3
  höchstens 2), beim Ruhezustand, bei gesperrtem Bildschirm und beim Benutzerwechsel. Eine offene Bearbeitung wird
  vorher gespeichert.
- **Datenverlust.** Speichern mit Kontrolle (die neue Datei wird zurückgelesen und entschlüsselt, bevor sie die
  alte ersetzt), automatische Sicherungen, «Zuletzt gelöscht» (30 Tage), Notfallcode mit Tippfehler-Korrektur,
  nur eine laufende Siegel-Instanz.
- **Teilweise: ein übernommener Mac während der Sitzung.** Einträge mit Schutz 2–5 begrenzen den Schaden auf einen
  Eintrag pro Touch-ID-Berührung (Abschnitt 10).

## 2. Wogegen Siegel nicht schützt

- **Schadsoftware auf deinem Mac**, vor allem solche mit Administratorrechten. Sie kann mitlesen, was du
  tippst, den Arbeitsspeicher auslesen, während der Tresor offen ist, oder dir eine gefälschte Siegel-App
  unterschieben. Schutz pro Eintrag macht das nur langsamer (Abschnitt 10).
- **Programme mit Bedienungshilfen-Recht** (Fernwartung, KI-Steuerung, Automatisierung). Sie können Siegel
  bedienen wie du und damit alles sehen, was entsperrt sichtbar ist.
- **Jemand am entsperrten Mac.** Die Auto-Sperre verkürzt das Zeitfenster, mehr nicht.
- **Alte Kopien** in Time Machine, iCloud oder auf USB-Sticks. Sie lassen sich mit dem Passwort, den Faktoren und
  dem Notfallcode öffnen, die damals galten.
- **Ohne FileVault** liegen Nebenprodukte (CSV-Exporte, Druckaufträge, Arbeitsspeicherabbilder)
  ungeschützt auf der Festplatte.
- **Wer das Notfallkit (bzw. zwei Teile) und eine Kopie der Datei hat**, braucht weder Passwort noch Faktoren
  (Abschnitt 8).

Die Einzelheiten stehen in den Abschnitten 7 bis 11.

## 3. So funktioniert die Verschlüsselung

Der Inhalt des Tresors ist mit einem **Tresorschlüssel** verschlüsselt: 256 Bit reiner Zufall, bei jedem
Zugangswechsel (neues Master-Passwort, neues Notfallkit, neue Stufe, Wiederherstellung) neu gezogen. Dieser Schlüssel
liegt zweimal verpackt in der Datei. Jeder der beiden Zugänge öffnet seine Verpackung für sich allein:

```
Master-Passwort ──Argon2id──┐
Touch ID       (Stufe 2–5) ─┤
QR-Karte       (Stufe 4–5) ─┼──HKDF──► Schlüssel 1 ──┐
Sicherheitsschlüssel  (5) ──┘                        ├──► Tresorschlüssel ──► Inhalt
Notfallcode ──────────ML-KEM-1024 + X25519──► Schlüssel 2 ──┘
(Stufen 4/5: zwei von drei Teilen ergeben den Code)
```

Jeder Faktor liefert 32 geheime Bytes, die in Schlüssel 1 eingehen. Fehlt einer oder ist er falsch, entsteht ein
falscher Schlüssel. Siegel prüft also nicht «ist der Finger richtig?» und öffnet dann, sondern der Finger ist Teil
der Rechnung (Abschnitt 9).

### Argon2id: Raten teuer machen

Aus dem Master-Passwort wird mit **Argon2id** ein Schlüssel berechnet. Argon2 hat 2015 die Password Hashing
Competition gewonnen, die Variante Argon2id ist als RFC 9106 standardisiert. Sie ist absichtlich langsam und
braucht viel Arbeitsspeicher: im Profil «Standard» pro Versuch **1 GiB und drei Durchgänge**, etwa 1.2
Sekunden auf einem M5 Max. Beim Entsperren merkst du das kaum. Wer aber Milliarden Passwörter durchprobieren
will, braucht für jeden gleichzeitigen Versuch 1 GiB Speicher. Darum helfen Grafikkarten und Spezialchips hier
viel weniger als bei gewöhnlichen Verfahren. Das Profil «Stark» (2 GiB, vier Durchgänge, etwa 3.3 s) macht
jeden Versuch rund 2.7-mal teurer; ab Stufe 3 ist es fest eingestellt.

Jede Verpackung bekommt ein neues Zufallssalz. Vorberechnete Tabellen nützen deshalb nichts, und jeder
Tresor muss einzeln angegriffen werden.

**Standardmässig gibt es keine Versuchsgrenze** und keine Selbstlöschung nach Fehleingaben. Ein Angreifer kopiert
die Datei ohnehin und probiert auf seinen eigenen Rechnern, eine Sperre in Siegel würde ihn nicht aufhalten. Sie
würde nur dich aussperren. Die Bremse ist Argon2id. Wer trotzdem eine Grenze will, kann in Stufe 4/5 die
Selbstvernichtung für ausgewählte Einträge einschalten (Abschnitt 11). Sie vernichtet nie den ganzen Tresor.

### XChaCha20-Poly1305: verschlüsseln und versiegeln

Verschlüsselt wird mit **XChaCha20-Poly1305**. Jede Verschlüsselung erhält eine neue Zufallszahl, und an den
verschlüsselten Text wird ein Prüfwert angehängt. Wird auch nur ein Bit verändert, passt der Prüfwert nicht
mehr, und Siegel verweigert das Öffnen. Der Dateikopf mit den Argon2-Einstellungen und den Faktoren ist
mitversiegelt: Wer die Einstellungen herabsetzt, um schneller raten zu können, oder einen Faktor aus dem Kopf
streicht, erhält eine Datei, die sich mit keinem Passwort mehr öffnen lässt. Der Inhalt wird vor dem Verschlüsseln
auf Blöcke von 16 KiB aufgefüllt, damit die Dateigrösse nur grob verrät, wie viel drinsteht.

### Der Notfallschlüssel: hybrid ML-KEM-1024 + X25519

Der Notfallcode (55 Zeichen in 11 Gruppen) enthält 256 Bit reinen Zufall. Er wird nirgends gespeichert.
Siegel leitet daraus ein Schlüsselpaar ab. In der Datei steht nur die öffentliche Hälfte, vergleichbar mit
einem offenen Vorhängeschloss: Zuschliessen kann jeder damit, öffnen nur der Code. So kann Siegel den
Tresorschlüssel nach jedem Wechsel neu für den Notfallweg verpacken, ohne den Code zu kennen. Dein
gedrucktes Blatt bleibt gültig, bis du bewusst ein neues Notfallkit erstellst.

Das Vorhängeschloss ist doppelt:

- **ML-KEM-1024**: 2024 von der US-Normenbehörde NIST als FIPS 203 standardisiert, höchste Stufe (5). Es
  beruht auf Gitterproblemen, gegen die kein schneller Quantenalgorithmus bekannt ist.
- **X25519**: ein seit Jahren bewährtes klassisches Verfahren (unter anderem in Signal, TLS und SSH).

Beide Ergebnisse werden zusammengemischt. Ein Angreifer muss **beide** brechen. ML-KEM ist noch jung: Zeigt
sich darin eine Schwäche, hält X25519 gegen heutige Rechner. Bricht ein Quantenrechner eines Tages X25519,
hält ML-KEM.

Weil der Code reiner Zufall ist, braucht er kein Argon2: 2^256 Möglichkeiten lassen sich nicht
durchprobieren.

In den **Stufen 4 und 5** teilt Siegel den Code nach Shamir in drei Teile (2 aus 3): Je zwei Teile ergeben den Code,
ein einzelner Teil verrät mathematisch nichts über ihn. So schadet ein verlorener oder gesehener Teil allein nicht,
und ein verlorener Teil sperrt dich nicht aus.

### Warum das gegen Quantenrechner hält

«Jetzt mitschneiden, später entschlüsseln»: Ein Angreifer könnte deine Datei heute kopieren und warten, bis
es grosse Quantenrechner gibt. Was die nach heutigem Wissen können:

- **Shor-Algorithmus**: bricht RSA und elliptische Kurven wie X25519 und P-256. Das betrifft in Siegel den
  Notfallweg (dort steht ML-KEM daneben) und den Touch-ID-Faktor (Abschnitt 9). Der Passwortweg nutzt gar kein
  solches Verfahren.
- **Grover-Algorithmus**: beschleunigt das Durchprobieren, aber nur «mit der Quadratwurzel». Aus 2^256
  Versuchen werden etwa 2^128 Schritte. Das liegt weit ausser Reichweite, zumal sich Grover schlecht auf viele
  Maschinen verteilen lässt. Darum sind alle symmetrischen Schlüssel in Siegel 256 Bit lang: Selbst halbiert
  bleiben 128 Bit, und 128 Bit gelten heute auch ohne Quantenrechner als sicher.
- **Grover gegen das Master-Passwort**: Theoretisch würde Grover auch das Raten beschleunigen (aus 60 Bit
  würden 30 Bit Schritte). Dafür müsste aber jeder einzelne Versuch, also Argon2 mit 1 GiB, vollständig im
  Quantenrechner laufen. Allein der Speicher dafür wären rund 8.6 Milliarden fehlerkorrigierte Qubits (2^33 Bit);
  heutige Geräte haben einige hundert bis wenige tausend fehleranfällige. Das ist nicht absehbar.

**Was «quantensicher» hier heisst und was nicht:** Die verwendeten Verfahren gelten nach heutigem Stand der
Forschung als sicher gegen alle bekannten Quantenalgorithmen, mit einer Ausnahme: Die Secure Enclave kann nur das
klassische P-256 (Abschnitt 9). Unknackbar heisst das alles nicht. Mathematische Durchbrüche und Programmierfehler
(in Siegel, CryptoKit oder libsodium) bleiben möglich. Und das schwächste Glied ist fast nie die Mathematik, sondern
das Master-Passwort, das Notfallkit oder der Mac selbst.

## 4. Was ein Angriff auf eine gestohlene Datei kostet

Annahmen: Der Angreifer hat die Datei, Stufe 1, Profil «Standard» (1 GiB, drei Durchgänge). «Erwartet» heisst: Im
Mittel findet er das Passwort nach der Hälfte aller Möglichkeiten. Alle Zahlen sind **Grössenordnungen**,
keine Messwerte, ausser dort, wo «gemessen» steht.

Tempo pro Gerät:

| Gerät | Versuche pro Sekunde |
|---|---|
| MacBook Pro M5 Max, 1 Thread | 0.85 (gemessen, ≈ 1.2 s pro Versuch) |
| MacBook Pro M5 Max, 8 Threads | etwa 5 (8 GiB Speicher gleichzeitig belegt) |
| Grafikkarte RTX 5090 (32 GB) | geschätzt 10–50 (höchstens rund 30 Versuche gleichzeitig) |
| Spezial-Hardware im grossen Stil | Annahme: etwa 5·10^-8 USD pro Versuch, Strom und Geräte eingerechnet |

| Stärke | Zum Vergleich | Erwartete Versuche | Ein M5 Max (5/s) | Eine RTX 5090 (10–50/s) | Kosten mit Spezial-Hardware |
|---|---|---|---|---|---|
| 20 Bit | `Sommer2025!` (15 Bit), `Michael1985` (14 Bit) | 5·10^5 | etwa 1 Tag | 3–15 Stunden | wenige Cent |
| 30 Bit | `Sabine1972!` (26 Bit), `Thomas.Meier1979` (34 Bit) | 5·10^8 | etwa 3 Jahre | 4 Monate – 2 Jahre | etwa 27 USD |
| 40 Bit | | 5·10^11 | etwa 3'500 Jahre | 350–1'700 Jahre | etwa 27'000 USD |
| 50 Bit | 4 Zufallswörter (44 Bit), `correcthorsebatterystaple` (48 Bit) | 6·10^14 | Millionen Jahre | 0.4–2 Mio. Jahre | etwa 28 Mio. USD |
| 60 Bit | Mindestwert für das Master-Passwort | 6·10^17 | Milliarden Jahre | Hunderte Mio. bis Milliarden Jahre | etwa 3·10^10 USD |
| 66 Bit | Passphrase aus 6 Wörtern (Siegel-Vorschlag) | 4·10^19 | – | – | etwa 2·10^12 USD |
| 80 Bit | | 6·10^23 | – | – | etwa 3·10^16 USD |

So liest man die Tabelle:

- Die Zeit spielt kaum eine Rolle, ein ernsthafter Angreifer kauft Rechenleistung. Entscheidend ist die
  rechte Spalte.
- Unter 40 Bit lohnt sich ein Angriff für jeden, der es gezielt auf dich abgesehen hat. Ab 60 Bit lohnt sich
  Raten für niemanden mehr; ein Angreifer würde eher versuchen, an deinen entsperrten Mac oder an dein
  Notfallkit zu kommen.
- Hardware wird billiger. Grobe Annahme: in 10–20 Jahren um den Faktor 10 bis 100. Darum verlangt Siegel
  mindestens 60 Bit und schlägt eine 66-Bit-Passphrase vor. Das Profil «Stark» (fest ab Stufe 3) verteuert jede
  Zeile um etwa den Faktor 2.7.
- Die Bit-Zahl eines selbst ausgedachten Passworts ist eine **Schätzung** (siehe Abschnitt 5). Die 66 Bit der
  vorgeschlagenen Passphrase sind dagegen exakt: echter Zufall, vom Computer gezogen.
- **Ab Stufe 2** gilt die Tabelle nur für jemanden, der zusätzlich alle Faktoren hat. Ohne den Touch-ID-Faktor (32
  Byte Zufall, berechnet in der Secure Enclave dieses Macs) nützt Raten nichts, egal wie schwach das Passwort ist.
  Die Ausnahme steht in Abschnitt 9: Wer die ganze Festplatte samt Schlüsseldatei und künftig einen Quantenrechner
  hat, kann diesen Faktor berechnen; ab Stufe 4 fehlen ihm dann immer noch Karte bzw. Schlüssel.

## 5. Das Master-Passwort

**Regel** (im Kern erzwungen, nicht nur in der Oberfläche): geschätzte Stärke mindestens 60 Bit, mindestens
12 Zeichen, höchstens 1024 Byte. Die Schätzung arbeitet wie zxcvbn (von Dropbox) mit deutschen und
Schweizer Listen: Sie erkennt häufige Passwörter, Wörter, Vor- und Nachnamen, Orte, Kantone, Vereine,
Jahreszahlen, Daten, Tastaturmuster (QWERTZ und QWERTY), Wiederholungen und Ersetzungen wie `@` für `a`.
Dein Benutzername und das Wort «siegel» zählen als bekannt.

Abgelehnt werden zum Beispiel `Passwort2026!`, `Sommer2026!!!`, `Qwertz123456!`, `YB-Meister-2026` und
auch der Satz `Mein Hund heisst Bello` (54.5 Bit). Diese Passwörter sehen lang aus, folgen aber Mustern, die
Angreifer zuerst probieren.

**Warum Passphrasen:** Menschen sind schlechte Zufallsgeneratoren. Was sich wie ein eigener Einfall anfühlt
(Name, Jahr, Ausrufezeichen), steht in den Ratelisten weit vorn. «Passphrase vorschlagen» zieht 6 Wörter
zufällig aus einer Liste mit genau 2048 deutschen Wörtern: 2048^6 = 2^66 Möglichkeiten. Das ist echte
Zufälligkeit, keine Schätzung, und trotzdem gut zu merken und zu tippen.

- Ein paarmal **Neu würfeln**, bis dir eine gefällt, ist in Ordnung: Zehnmal kostet höchstens etwa 3 Bit.
- Die Wörter nicht umstellen, nicht durch eigene ersetzen, kein Beispiel aus einer Anleitung übernehmen.
- Das Master-Passwort nirgends sonst verwenden. Siegel warnt, wenn ein Eintrag im Tresor dasselbe Passwort
  hat («Gleich wie Master-Passwort»).
- In den ersten Tagen oft eintippen, bis es sitzt. Das Notfallkit ist die Rückversicherung, nicht ein
  aufgeschriebenes Master-Passwort.

Grenzen der Schätzung: Sie kennt kein Sprachmodell. Sehr lange natürliche Sätze gelten als stark, obwohl
ein Angreifer mit Grammatikwissen schneller wäre. Seltene Wörter, Dialekt und zusammengesetzte Wörter zählen
wie Zufallszeichen und werden eher überschätzt; ab etwa vier Ortsnamen mit Postleitzahl ist sie wieder zu
optimistisch. Einzelheiten in `Sources/SiegelCore/Staerke/Woerter/HERKUNFT.md`, Abschnitt «Grenzen (ehrlich)». Wer
sicher gehen will, nimmt die Passphrase.

## 6. Das Notfallkit

Das Notfallkit ist ein Blatt mit dem Notfallcode und der Kit-Kennung, in den Stufen 4/5 drei Blätter mit je einem
Teil. Damit öffnest du den Tresor, wenn du das Master-Passwort vergisst oder ein Faktor fehlt. **Wer das Blatt (bzw.
zwei Teile) und eine Kopie der Tresordatei hat, hat alle Passwörter, ohne Master-Passwort und ohne Faktoren** –
ausser den vernichtbaren Einträgen (Abschnitt 11).

- **Nur auf Papier.** Kein PDF, keine Notiz-App, keine Cloud, kein Foto: Live Text macht den Code in Fotos
  durchsuchbar, und iCloud-Fotos verteilt ihn auf alle Geräte. Siegel bietet darum weder Kopieren noch PDF an.
- **Abschreiben ist der sicherste Weg.** Beim Drucken zeigt Siegel keine Vorschau und nennt den Auftrag
  «Dokument». Wählt jemand im Druckdialog «Als PDF sichern», steht statt des Codes ein Hinweis auf dem Blatt.
  Trotzdem:
  - macOS behält gedruckte Aufträge bis **24 Stunden** in der Druckwarteschlange (`/private/var/spool/cups`,
    nur mit Administratorrechten lesbar; Standard von CUPS: `PreserveJobFiles 86400`). Ohne FileVault liegt das
    Blatt so lange unverschlüsselt auf der SSD.
  - **Netzwerkdrucker** empfangen oft unverschlüsselt (ipp, socket, lpd, smb), und Firmendrucker speichern
    Aufträge häufig auf einer eigenen Festplatte. Siegel warnt dann vor dem Druck. Am Arbeitsplatz oder in der
    Schule: abschreiben.
- **Aufbewahren**: getrennt vom Mac und getrennt von Sicherungen, zum Beispiel in einem Couvert bei der
  Familie oder im Bankschliessfach. Die drei Teile an drei verschiedenen Orten, zum Beispiel zuhause, im
  Bankschliessfach und bei einer Vertrauensperson. Die Kit-Kennung (`XXXX-XXXX`, nicht geheim) zeigt, zu welchem
  Tresor ein Blatt gehört; Siegel zeigt sie unter Einstellungen.
- **Bestätigen**: Nach dem Abschreiben oder Drucken tippst du zwei zufällig gewählte Gruppen ein (bei drei Teilen
  je Teil eine). Bis dahin steht im Tresor «Notfallkit nicht bestätigt – jetzt einrichten».
- **Ab und zu prüfen**: Einstellungen → «Notfallcode prüfen…» prüft Code bzw. zwei Teile, ohne etwas zu ändern.
- **Unleserlich?** Ein `?` steht für ein unleserliches Zeichen (bis 4). Siegel korrigiert auch 1–2 falsche
  Zeichen oder vertauschte Nachbarn und zeigt die korrigierten Stellen zur Bestätigung an.
- **Blatt verloren oder gesehen worden?** Einstellungen → «Neues Notfallkit…», auch wenn nur ein Teil von dreien
  betroffen ist. Danach den alten Code als ungültig betrachten und die Frage «Bisherige Sicherungen entfernen?» mit
  «Entfernen» beantworten. Kopien ausserhalb von Siegel (Time Machine, Cloud) lassen sich mit dem alten Code weiterhin
  öffnen (Abschnitt 7).
- **Nach einer Wiederherstellung** mit dem Code: Inhalt prüfen (siehe Abschnitt 1, Notfallweg). Die
  Wiederherstellung setzt Tresor und alle Einträge auf Stufe bzw. Schutz 1 zurück (Abschnitt 8).

## 7. Grenzen im Detail

### Schadsoftware und Administratorrechte

Läuft Schadsoftware mit deinen Benutzerrechten oder als Administrator (root), ist kein Passwort-Manager sicher.
Sie kann den Arbeitsspeicher auslesen, während der Tresor offen ist, und das Siegel-Programm austauschen (es
liegt in `~/Applications`, also in deinem Benutzerordner). Die Sandbox von Siegel schützt nicht vor anderen
Programmen desselben Benutzers. Siegel schaltet beim Tippen des Master-Passworts und des Notfallcodes die
«sichere Tastatureingabe» von macOS ein, damit gewöhnliche Programme die Tasten nicht mitlesen; gegen
Administratorrechte hilft das nicht. Die Prüfung der eigenen Signatur beim Start erkennt beschädigte oder
nachträglich veränderte Bündel, aber keinen Angreifer mit deinen Rechten (eine ad-hoc-Signatur lässt sich neu
setzen). Was der Schutz pro Eintrag in diesem Fall noch leistet, steht in Abschnitt 10. Schutz: macOS aktuell
halten, Programme nur aus vertrauenswürdigen Quellen, keine fremden Administrator-Passwortabfragen bestätigen.

### Bedienungshilfen: Fernwartung und KI-Steuerung

Programme mit dem Recht «Bedienungshilfen» (Systemeinstellungen → Datenschutz & Sicherheit → Bedienungshilfen)
können Siegel bedienen wie du: das Auge anklicken, «Kopieren» drücken und die Zwischenablage lesen. Dazu
gehören Fernwartung (TeamViewer, Bildschirmfreigabe), Automatisierungs-Werkzeuge und **KI-Assistenten, die den
Mac steuern**. Siegel blendet Passwörter für solche Programme aus (ausser VoiceOver ist an), aber was entsperrt
auf dem Bildschirm erreichbar ist, kann ein solches Programm sich holen. **Darum vor jeder Fernwartung oder
KI-Steuerung Siegel sperren (⌘L).** Die Liste der berechtigten Programme ab und zu durchsehen.

### Bildschirmaufnahmen

Siegel bittet macOS, alle seine Fenster (auch Dialoge) aus Bildschirmfotos, Aufnahmen und Freigaben
herauszuhalten. Das ist eine Bitte an das System, kein harter Schutz: Ob sich ein bestimmtes Aufnahme- oder
Fernwartungsprogramm daran hält, hängt vom Programm und von der macOS-Version ab. Geprüft wird das mit
`PRUEFLISTE.md`, Abschnitt B1.

### Texte im Arbeitsspeicher

Schlüssel, Notfallcode und der entschlüsselte Tresorinhalt (bevor er in Einträge zerlegt wird) liegen in
geschütztem Speicher (gesperrt gegen Auslagern, mit Schutzseiten, beim Freigeben genullt). Die einzelnen
Einträge (Titel, Benutzername, Passwort, Notizen) sind aber für die Oberfläche gewöhnliche Swift-Texte, und
auch das Master-Passwort läuft beim Tippen durch ein Textfeld des Systems. Solche Texte lassen sich in Swift
**nicht zuverlässig mit Nullen überschreiben**. Siegel verwirft beim Sperren alle Verweise darauf; die Bytes
können aber im freigegebenen Speicher liegen bleiben, bis er neu benutzt wird. Gefährlich wird das nur für
jemanden, der den Speicher lesen kann (Schadsoftware mit Administratorrechten, Absturzberichte,
Arbeitsspeicherabbild ohne FileVault). Aufgedeckte Geheimteile geschützter Einträge sind ebenfalls solche Texte,
solange sie aufgedeckt sind.

### Absturzberichte

Stürzt Siegel ab, schreibt macOS einen Absturzbericht (`~/Library/Logs/DiagnosticReports`). Er kann die
Inhalte der Prozessor-Register zum Absturzzeitpunkt enthalten, und darin können Bruchstücke eines Passworts
stehen. Siegel schreibt selbst nie Inhalte in Fehlermeldungen oder Protokolle (der Bau bricht ab, wenn der Code
das versucht) und schaltet vollständige Speicherabbilder (Core Dumps) ab. Ist «Mac-Analysedaten teilen» an,
gehen Absturzberichte an Apple. **Empfehlung:** Systemeinstellungen → Datenschutz & Sicherheit → Analyse &
Verbesserungen → «Mac-Analysedaten teilen» ausschalten.

### Zwischenablage und Zwischenablageverlauf

Siegel kopiert nur auf diesem Mac (nicht über die «Universelle Zwischenablage» auf iPhone oder iPad), markiert
den Inhalt als vertraulich und vergänglich (Typen `org.nspasteboard.ConcealedType` und `TransientType`) und
leert die Zwischenablage nach 30 Sekunden (einstellbar 15–90), beim Sperren, beim Beenden und nach einem
Absturz beim nächsten Start. Hast du inzwischen etwas anderes kopiert, lässt Siegel das stehen. Siegel liest
den Inhalt der Zwischenablage nie. In den Stufen 3–5 sperrt Siegel beim Wechsel in ein anderes Programm, lässt ein
eben kopiertes Passwort aber bis zum Ablauf stehen (höchstens 15 Sekunden) – sonst liesse es sich nirgends einfügen.
Ruhezustand, Bildschirm aus, Bildschirmsperre und Benutzerwechsel leeren auch dann sofort. Für Einträge mit Schutz
3–5 gilt höchstens 15 Sekunden, auch für ⌘C aus dem Passwortfeld beim Bearbeiten.

Grenzen: Solange ein Passwort in der Zwischenablage liegt, kann jedes Programm es lesen. macOS 26 hat einen
eigenen **Zwischenablageverlauf** in Spotlight. Ob er die Markierung «vertraulich» beachtet, hat Apple nicht
dokumentiert. Bis das geprüft ist (`PRUEFLISTE.md`, Abschnitt B2): den Verlauf in den Spotlight-Einstellungen
ausschalten. Zwischenablage-Programme wie Raycast, Paste oder Maccy beachten die Markierung in der Regel,
aber nicht garantiert.

### Externe Bildschirme, Sidecar, Spiegeln

Liegt das Siegel-Fenster auf einem externen Bildschirm (Monitor, AirPlay-Bildschirm, **Sidecar** mit dem
iPad), bleiben sichtbare Passwörter, der Notfallcode, die Schlüsselkarte im Assistenten und die Kamera-Vorschau
beim Scannen der Karte verdeckt (die Karte wird trotzdem erkannt), solange die Einstellung «Geheimnisse auf
externen Bildschirmen zeigen» aus ist (Standard). **Beim Spiegeln** (AirPlay-Synchronisierung, Beamer,
Bildschirm duplizieren) erkennt Siegel das Spiegel-Set und verdeckt ebenfalls; mit echter Hardware ist das erst
geprüft, wenn `PRUEFLISTE.md` Abschnitt B3 abgehakt ist. Titel, Benutzernamen und Websites zeigt jeder Bildschirm.
Vor dem Präsentieren Siegel trotzdem sperren.

### Alte Kopien: Time Machine, Cloud, USB

Die Tresordatei ist immer verschlüsselt, auch in Time Machine und in der Cloud. Jede Kopie lässt sich aber
mit dem Master-Passwort, den Faktoren und dem Notfallcode öffnen, **die zum Zeitpunkt der Kopie galten**. Wechselst
du das Master-Passwort, weil es jemand gesehen haben könnte, öffnet das alte Passwort weiterhin alle alten Kopien;
erhöhst du die Stufe, öffnen alte Kopien weiterhin ohne die neuen Faktoren. Siegel fragt nach jedem Zugangswechsel,
ob es die eigenen Sicherungen (auch am zweiten Sicherungsort) entfernen soll. Time Machine, iCloud-Versionen und von
Hand exportierte Sicherungen erreicht Siegel nicht; die musst du selbst löschen.

Wichtiger noch: Hatte jemand eine alte Kopie **und** das alte Passwort, kennt er den damaligen Inhalt. Dann
hilft nur, die wichtigen Passwörter im Tresor selbst zu ändern.

### CSV-Dateien

Eine CSV-Datei (Import aus dem Browser, Export aus Siegel) enthält alle Passwörter im Klartext. **Sobald sie
auf der Festplatte lag, gilt sie als möglicherweise kompromittiert**, auch nach dem Löschen: SSDs verteilen
Schreibvorgänge und löschen nicht sofort physisch, APFS-Schnappschüsse und Time Machine können Kopien halten,
Vorschaubilder und Suchindex merken sich Inhalte, und Schreibtisch- und Dokumente-Ordner werden eventuell mit
iCloud abgeglichen. Siegel mildert das (Export nur in einen Ordner, den Spotlight nicht durchsucht, nie nach
iCloud Drive, vom Backup ausgenommen, Angebot zum endgültigen Löschen), verhindern kann es das nicht. Deshalb:
CSV nur so kurz wie nötig behalten, nie mit Excel oder Numbers öffnen, und Passwörter aus einer CSV, die
ohne FileVault, im Downloads-Ordner oder in einem Cloud-Ordner lag, als bekannt betrachten und die wichtigen
ändern. In den Stufen 4/5 gibt es keinen CSV- und KeePass-Export; Einträge mit Schutz 4/5 fehlen in jedem Export.
Der KeePass-Export ist mit einem eigenen Export-Passwort verschlüsselt: Wer die Datei und dieses Passwort hat, hat
alle exportierten Passwörter, ohne Touch ID, Karte oder Schlüssel.

### FileVault

Siegel verschlüsselt den Tresor selbst und braucht FileVault dafür nicht. **FileVault schützt aber alles
rundherum**: CSV-Exporte, Druckaufträge, Arbeitsspeicherabbilder beim Ruhezustand, Reste gelöschter Dateien und
überschriebener Schlüsseldateien (Abschnitt 11). Ohne FileVault ist die SSD eines Apple-Silicon-Macs zwar intern
verschlüsselt, der Schlüssel ist aber nicht an dein Anmeldepasswort gebunden: Wer den Mac in die Hände bekommt,
kommt leichter an die Dateien.

Einschalten: Systemeinstellungen → Datenschutz & Sicherheit → FileVault. Auf Apple-Silicon-Macs geht das
sofort, weil die Daten schon verschlüsselt sind. Den FileVault-Wiederherstellungsschlüssel nicht nur in Siegel
ablegen, denn Siegel liegt auf genau diesem Mac. Siegel zeigt bei der Einrichtung und unter Einstellungen →
Sicherheit einen Hinweis, solange FileVault aus ist.

### Webseiten und automatisches Ausfüllen

Siegel füllt heute nichts automatisch aus. Das heisst auch: Es merkt nicht, wenn du auf einer gefälschten Seite
bist. Adressen mit gemischten Schriften zeigt Siegel als Punycode an; eine Fälschung ganz in einer anderen
Schrift (etwa rein kyrillisch) erkennt es nicht. Die Adresse im Browser selbst vergleichen. Die vorbereitete
Autofill-Erweiterung (nur mit bezahltem Apple-Entwicklerkonto) würde nur bei gleichem Host oder einer Unterdomain
anbieten, nie `http` für einen `https`-Eintrag, nie Einträge mit Schutz 3–5 und in Stufe 4/5 gar nicht; mit dem
System ist sie ungetestet.

### 2FA-Codes im selben Tresor

Wer den Tresor öffnet, hat dann auch den zweiten Faktor dieser Konten. Für die wichtigsten Konten (E-Mail, Bank) die
2FA lieber in einer getrennten App halten, oder den Eintrag mindestens mit Schutz 2 versiegeln.

## 8. Sicherheitsstufen (v4)

Die Stufe bestimmt zwei Dinge: welche **Faktoren** zum Öffnen nötig sind (kryptografisch, im Dateikopf festgehalten)
und welche **Regeln** die Oberfläche einhält (im verschlüsselten Inhalt festgehalten).

| Stufe | Zum Öffnen (kryptografisch) | Schlüsselableitung | Im Notfall | Regeln der Oberfläche |
|---|---|---|---|---|
| 1 Standard | Passwort | Standard | ein Code | – |
| 2 Erhöht | Passwort + Touch ID | Standard | ein Code | – |
| 3 Hoch | Passwort + Touch ID | Stark | ein Code | Touch ID vor jedem Aufdecken/Kopieren, Sperre beim App-Wechsel, Zwischenablage ≤ 15 s, Auto-Sperre ≤ 2 Min. |
| 4 Maximal | Passwort + Touch ID + QR-Karte | Stark | zwei von drei Teilen | wie 3, neue Einträge mit Schutz 2, kein CSV-/KeePass-Export |
| 5 Festung | Passwort + Touch ID + Karte + Sicherheitsschlüssel | Stark | zwei von drei Teilen | wie 4 |

Was das ehrlich heisst:

- **Faktoren sind Mathematik, Regeln sind Oberfläche.** Ohne einen Faktor der Stufe entsteht ein falscher Schlüssel;
  eine Tür daran vorbei gibt es nicht. Die Regeln dagegen setzt das Programm um. Wer den Tresor geöffnet hat (also
  Passwort und alle Faktoren hatte), hat den Tresorschlüssel im Arbeitsspeicher. Einträge mit Schutz 1 sind damit
  lesbar, auch wenn die Oberfläche in Stufe 3–5 vor dem Aufdecken Touch ID verlangt. Gegen Schadsoftware in der
  Sitzung hilft nur der Schutz pro Eintrag (Abschnitt 10).
- **Der Notfallcode ersetzt Passwort und alle Faktoren**, auch in Stufe 5. Das Notfallkit (bzw. zwei der drei Teile)
  zusammen mit einer Kopie der Datei ist so viel wert wie alles zusammen. Die Stufe macht den Tresor also nicht
  sicherer als das Versteck deines Notfallkits. Eine Wiederherstellung setzt den Tresor auf Stufe 1 und alle Einträge
  auf Schutz 1; vernichtbare Einträge fallen weg.
- **Stufenwechsel** (auf- und abwärts) verlangt das Master-Passwort und alle Faktoren der aktuellen Stufe. Siegel
  erneuert dabei den Tresorschlüssel und das Salz und legt vorher eine angeheftete Sicherung an. Alte Sicherungen und
  Time-Machine-Kopien öffnen weiterhin mit dem alten Zugang, nach einer Erhöhung also **ohne die neuen Faktoren**.
  Darum nach dem Wechsel «Alte Sicherungen entfernen» wählen.
- **Sicherungen ab Stufe 2** sind an Touch ID dieses Macs gebunden (ab Stufe 4 zusätzlich an Karte bzw. Schlüssel).
  Den verlorenen oder defekten Mac überstehen sie nur zusammen mit dem Notfallkit (Abschnitt 12).
- **Stufe 5 trägt den Hinweis «mit echter Hardware ungetestet»** (Abschnitt 9), bis die Prüfung mit einem Gerät
  abgehakt ist.

## 9. Faktoren und ihre Grenzen

Jeder Faktor liefert beim Öffnen 32 geheime Bytes, die zusammen mit dem Argon2-Ergebnis in den Schlüssel eingehen.
Ein falscher Faktor ist von einem falschen Passwort nicht zu unterscheiden («Passwort oder ein Faktor stimmt
nicht»). Einzige Ausnahme ist die Karte: Eine kurze Kennung (32 Bit) im Kopf erkennt die falsche Karte, bevor
gerechnet wird; über die 256 Bit der Karte verrät sie nichts Nutzbares.

### Touch ID (Secure Enclave)

- **Wie**: Siegel legt in der Secure Enclave dieses Macs einen Schlüssel an (P-256, nur mit den jetzt eingerichteten
  Fingern nutzbar). Er verlässt den Chip nie. Auf der Festplatte liegt nur eine verschlüsselte Hülle davon
  (`Hardware/<keyID>.siegelhw`), nicht in der Tresordatei und vom Backup ausgenommen. Eine gestohlene Tresordatei
  oder Sicherung enthält von diesem Faktor nichts.
- **Klassisch, nicht quantensicher**: Die Secure Enclave kann nur P-256. Wer die ganze Festplatte samt Schlüsseldatei
  hat und künftig einen Quantenrechner, könnte diesen Faktor berechnen. Dann schützen noch Passwort/Argon2 und die
  übrigen Faktoren (Karte, Schlüssel), die hybrid mit ML-KEM-1024 arbeiten.
- **Nur dieser Mac, nur diese Finger**: Auf einem anderen Mac, nach dem Neuaufsetzen oder nachdem ein Fingerabdruck
  hinzugefügt oder entfernt wurde, ist der Schlüssel unbrauchbar. Dann öffnet nur noch der Notfallcode
  (Abschnitt 12).
- **Vorübergehend ist kein Verlust**: Ist Touch ID nach zu vielen Fehlversuchen gesperrt oder nicht erreichbar
  (Deckel zu, Tastatur mit Touch ID nicht verbunden), ist nichts verloren: Mac einmal mit dem Passwort entsperren bzw.
  Deckel öffnen und erneut versuchen. Siegel bietet dafür bewusst keinen Notfallweg an, denn er setzt den Tresor auf
  Stufe 1 zurück, und vernichtbare Einträge fallen dabei weg.
- **Stand der Prüfung**: Die Logik ist gegen eine Software-Nachbildung getestet (gleiche Rechnung, Abbruch und
  geänderte Finger nachgestellt). Mit echter Hardware sind bisher nur die Verfügbarkeit und das Anlegen eines
  Schlüssels geprüft; Einrichten und Entsperren mit echtem Finger stehen in `PRUEFLISTE.md` A2.

### QR-Schlüsselkarte

- **Wie**: 256 Bit Zufall als QR-Code auf Papier, daneben derselbe Code in Gruppen zum Abtippen. Siegel liest sie
  mit der eingebauten Kamera (nur bei Bedarf, Bilder werden nie gespeichert) oder du tippst den Code ab.
- **Was sie schützt**: Diebstahl und Zwang, solange sie getrennt vom Mac liegt. Wer den Mac und dein Passwort hat,
  aber nicht die Karte, kommt nicht hinein.
- **Was sie nicht schützt**: **Wer die Karte einmal sieht, kennt sie dauerhaft** – ein Foto, eine Kopie, das Bild der
  Kamera eines übernommenen Macs. Die Karte ist kein Gerät, sie rechnet nichts; sie ist ein aufgedrucktes Geheimnis.
  Gegen einen bereits übernommenen Mac hilft sie darum nicht. Nicht fotografieren: Live Text liest auch die
  Gruppen neben dem QR-Code.
- **Stand der Prüfung**: Die Erkennung ist mit erzeugten QR-Bildern getestet; die Kamera selbst wurde in Tests nie
  gestartet (`PRUEFLISTE.md` A3/A4).

### Sicherheitsschlüssel (FIDO2)

- **Wie**: eigene Umsetzung von CTAP2 über USB, Erweiterung hmac-secret. Der Schlüssel berechnet aus einem
  gespeicherten Salz einen geheimen Wert; ohne den Schlüssel und eine Berührung gibt es ihn nicht.
- **Mit echter Hardware ungetestet.** Alle Abläufe sind gegen einen nachgebauten Schlüssel nach CTAP 2.1 getestet und
  gefuzzt, auch mit kaputten Antworten, aber noch nie gegen ein echtes Gerät. Die Oberfläche sagt das ebenfalls. Bis
  `PRUEFLISTE.md` C1 abgehakt ist, gilt: Stufe 5 und Schutz 5 nur mit einem Testtresor ausprobieren.
- Schlüssel, die fürs Registrieren eine PIN oder Benutzerprüfung verlangen, lassen sich nicht einrichten. Siegel prüft
  die Herkunftsbescheinigung (Attestation) des Schlüssels bewusst nicht: Ein falscher Schlüssel liefert einfach einen
  falschen Wert und damit einen falschen Schlüssel.
- **Gleiche Grenze wie die Karte**: Für einen Tresor liefert der Schlüssel immer denselben Wert. Wer ihn auf einem
  übernommenen Mac einmal mitliest, braucht den Schlüssel danach nicht mehr.

## 10. Schutz pro Eintrag und ein übernommener Mac

Der Schutz pro Eintrag (1–5) versiegelt die Geheimteile eines Eintrags (Passwort, Notizen, frühere Passwörter,
2FA-Geheimnis) mit einem eigenen Schlüssel. In ihn gehen der Tresorschlüssel und die Faktoren des Schutzes ein:

- **Touch ID** (ab Schutz 2): Für jeden Eintrag gibt es einen eigenen Einmal-Schlüssel, den nur die Secure Enclave mit
  deinem Finger auflösen kann.
- **Karte und Sicherheitsschlüssel** (ab Schutz 4 bzw. 5): je ein hybrides ML-KEM-1024 + X25519-Schlüsselpaar.

Die Schutz-Stufe selbst ist mitversiegelt: Wer sie in der Datei herabsetzt, macht den Eintrag unlesbar. Aufgedeckt
wird bei jedem Mal neu, nichts wird zwischengespeichert.

**Gegen einen übernommenen Mac** (Schadsoftware mit Administrator- oder Kernelrechten, während der Tresor offen ist):

- Liste, Titel, Benutzernamen, Websites und alle Einträge mit Schutz 1 liegen offen, sobald der Tresor offen ist.
- Für Einträge mit Schutz 2–5 braucht die Schadsoftware für **jeden Eintrag eine eigene Touch-ID-Berührung**. Pro
  Berührung bekommt sie höchstens einen Eintrag. Sie kann aber die Anfrage gegen einen anderen Eintrag tauschen: Du
  siehst «Eintrag aufdecken» und legst den Finger auf, freigegeben wird ein anderer.
- Begrenzend ist dabei **nur Touch ID**. Karte und Sicherheitsschlüssel liefern jedes Mal denselben Wert (Abschnitt
  9); hat die Schadsoftware ihn einmal gesehen, braucht sie Karte und Schlüssel nicht mehr. Schutz 4/5 schützt also
  vor Diebstahl und Zwang besser als Schutz 2/3, gegen einen übernommenen Mac aber nicht.
- **Einmal pro Gruppe**: Ein neues Notfallkit, ein Stufenwechsel mit neuem Kit, CSV- und KeePass-Exporte und das
  Einschalten der Selbstvernichtung geben die Einträge **einmal pro Gruppe gleich geschützter Einträge** frei, nicht
  pro Eintrag. Wer genau diese Freigabe abfängt, bekommt alle Einträge dieser Gruppe auf einmal. Solche Aktionen nur
  auf einem Mac machen, dem du vertraust.

Weitere Grenzen:

- **Offline-Bericht**: Für den Sicherheitsbericht speichert Siegel pro Eintrag eine Stärke-Stufe und eine
  Wiederverwendungs-Kennung. Wer Master-Passwort und Öffnungsfaktoren hat, aber nicht die Faktoren eines geschützten
  Eintrags, kann damit Vermutungen für dessen Passwort schnell prüfen und sieht die Stärke-Stufe. Erzeugte
  Zufallspasswörter sind so nicht zu erraten. Gegen eine gestohlene Datei ändert das nichts.
- **Sperren während einer Bearbeitung** (seit v4.4): Siegel speichert die offene Bearbeitung eines geschützten oder
  vernichtbaren Eintrags nur versiegelt, nie als offene Kopie. Ist der gewählte Schutz noch nicht eingerichtet, gilt
  der höchste eingerichtete (mindestens der bisherige), und der Sperrbildschirm sagt es. Lassen sich die Geheimteile
  nicht versiegeln (z. B. weil der Totmann-Schalter den Eintrag eben vernichtet hat), sind sie verloren – auch das
  sagt der Sperrbildschirm.
- **Notfallcode**: Er öffnet auch geschützte Einträge (ausser vernichtbare) und setzt sie auf Schutz 1 zurück.

## 11. Selbstvernichtung: was sie kann und was nicht (v4.3)

Nur in den Stufen 4/5 und nur für ausgewählte Einträge mit Schutz 4/5. Vernichtet wird ein eigener
Secure-Enclave-Schlüssel (Krypto-Löschung). Ohne ihn sind die markierten Einträge unlesbar, auch in jeder Sicherung
und jeder Kopie.

### Was sie kann

- **Drei Auslöser**, alle mit derselben Wirkung:
  - **Totmann-Schalter**: 7–365 Tage ohne echtes Entsperren.
  - **Fehlversuch-Zähler**: 10–100 falsche Passwörter in Folge.
  - **Vernichtungs-Passwort**: öffnet den Tresor scheinbar normal und vernichtet vorher still.
- **Wirkt auch gegen Kopien**: Wer die Festplatte vorher kopiert, umgeht zwar Zähler und Totmann-Schalter. Die
  Vernichtung wirkt trotzdem, weil der Schlüssel nur in der Secure Enclave dieses Macs liegt und den Finger braucht.
  Nach der Vernichtung nützen auch die Kopie und das Passwort nichts mehr.
- **Geht auch gesperrt**: Vernichten braucht keinen Tresorschlüssel. Der Totmann-Schalter prüft beim Start, beim
  Aktivieren und alle 10 Minuten.
- **Lässt den Rest unberührt**: Tresor und alle anderen Einträge bleiben, wie sie sind.
- **Vernichtungs-Passwort und Kopien** (seit v4.4): Die Ablage des Vernichtungs-Passworts ist an Finger, Karte und
  Sicherheitsschlüssel gebunden. Wer das Passwort kennt und den Container kopiert, liest ohne die Faktoren nichts –
  weder die Liste noch Einträge mit Schutz 1.

### Was sie nicht kann

- **Kein Notfallweg**: Markierte Einträge öffnet auch der Notfallcode nicht. Bei einer Wiederherstellung mit dem
  Notfallcode fallen sie ganz weg, und die Selbstvernichtung ist danach aus. Beim Markieren entfernt Siegel die älteren
  eigenen Sicherungen (sie enthielten die Einträge noch mit Notfallweg). **Time-Machine- und andere Kopien von vor dem
  Markieren erreicht Siegel nicht**: Eine solche Kopie öffnet mit dem damaligen Notfallcode auch die Einträge, die du
  später markiert hast.
- **Reste auf der SSD**: Auf einer SSD ohne FileVault und in lokalen APFS-Schnappschüssen (bis etwa 24 h, beachten
  den Backup-Ausschluss nicht) kann die alte Schlüssel-Hülle physisch liegen bleiben – nutzbar nur mit diesem Mac und
  deinem Finger.
- **Zustand im Container ist nicht geheim** (`Hardware/zustand.json`, nicht signiert):
  - Wer ihn löscht oder ändert, schaltet Zähler, Totmann-Schalter und Vernichtungs-Passwort bis zum nächsten echten
    Entsperren aus.
  - Wer ihn ändert, kann damit auch eine Vernichtung auslösen (abgelaufene Frist, Zähler an der Schwelle, Vermerk
    «vernichtet»), und gelöscht wird die Schlüsseldatei, die er nennt. Gesperrt kann Siegel ihn nicht prüfen. Das gibt
    niemandem mehr, als er ohnehin kann: Wer dort schreiben darf, kann jede Schlüsseldatei auch direkt löschen.
    Siegel lässt sich so aber nicht aussperren: Den Schlüssel zum Entsperren löscht es nie – auch nicht, wenn die
    Tresordatei fehlt (dann gilt das für die Schlüssel der eigenen Sicherungen) –, und beim Entsperren mit dem
    Master-Passwort, beim Speichern und beim Notfallcode auch keinen anderen Schlüssel, den der Tresor oder seine
    Sicherungen noch brauchen (seit v4.5). Nennt ein veränderter
    Zustand im gesperrten Zustand den Schlüssel der geschützten Einträge, sind diese bis zum Notfallcode unlesbar – wie
    wenn jemand die Datei löscht.
  - Er nennt, dass ein Vernichtungs-Passwort eingerichtet ist. Dass dessen Ablage wie eine Schlüsseldatei aussieht,
    hilft nur gegen einen flüchtigen Blick.
  - Nach einer Vernichtung vermerkt er sie samt Auslöser (z. B. «Vernichtungs-Passwort») und Datum. Wer die Dateien
    lesen kann, sieht also, dass das Vernichtungs-Passwort benutzt wurde.
  - Der Sperrbildschirm verrät es nicht: Die Totmann-Frist verschwindet nach jeder Vernichtung, wie nach einem echten
    Entsperren (v4.4).
- **Uhr**: Wer die Uhr zurückstellt, hält den Totmann-Schalter an; wer sie vorstellt, löst ihn aus. Läuft Siegel nie,
  vernichtet der Totmann-Schalter nichts (kein Hintergrunddienst).
- **Zähler**:
  - Deine eigenen Tippfehler zählen mit, auch bei «Tresor fehlt», «Beschädigt» und «Sicherung einspielen…», frühere
    Passwörter für ältere Sicherungen eingeschlossen.
  - Ab der Hälfte warnen der Sperrbildschirm und diese Bildschirme; die Meldung zum falschen Passwort sagt dort schon
    vorher, dass der Versuch zählt (v4.4).
  - Wer den Prozess genau zwischen Prüfung und Vermerk beendet, spart einen Versuch.
- **Vernichtungs-Passwort unter Zwang**:
  - Es öffnet den Tresor scheinbar normal, verlangt die Faktoren der Stufe wie sonst und dauert gleich lang. Dafür
    laufen beide Argon2 gleichzeitig, das braucht doppelt so viel Arbeitsspeicher.
  - Es schützt nur die markierten Einträge. Alles andere sieht, wer dich zwingt.
  - Alles, was das Master-Passwort verlangt (Passwort ändern, Notfallkit, Stufe, Selbstvernichtung), scheitert in
    dieser Sitzung mit «Passwort stimmt nicht». Wer das mehrfach probiert, kann Verdacht schöpfen. Die Einstellungen
    zeigen die Auslöser, aber keine markierten Einträge.
  - Wer diese Datei gelesen hat, weiss, dass es Vernichtungs-Passwörter gibt.
- **Vernichtungs-Sitzung und Tresorschlüssel**: Die Vernichtungs-Sitzung arbeitet mit dem echten Tresorschlüssel.
  Darum erneuert Siegel ihn beim nächsten Entsperren mit dem Master-Passwort (das dauert dann einmal etwas länger)
  und ebenso, wenn du das Vernichtungs-Passwort änderst oder entfernst. Wer bis dahin den Tresorschlüssel aus dem
  Speicher des entsperrten Macs holt (Werkzeug während der Sitzung), liest damit Kopien der Tresordatei bis zu dieser
  Erneuerung.
- **Ablagen aus v4.3** (vor dem 17.10.2026) waren noch nicht an die Faktoren gebunden: Eine Kopie davon öffnet mit dem
  Vernichtungs-Passwort den damaligen Tresorschlüssel, bis er wechselt (Passwort, Stufe, Notfallkit oder
  Vernichtungs-Passwort ändern). Siegel ersetzt die Ablage selbst beim nächsten echten Entsperren.
- **Was bleibt**: Vernichtet werden Passwort, Notizen, frühere Passwörter und 2FA-Geheimnis. Titel, Benutzer und
  Website bleiben bis «Entfernen» sichtbar, ebenso die Wiederverwendungs-Kennung des Berichts: Wer das Master-Passwort
  hat, kann damit Vermutungen für ein vernichtetes Passwort prüfen (erzeugte Passwörter sind so nicht zu erraten).
- **Ungewollte Vernichtung ist endgültig**: ein vergessener Totmann-Schalter in den Ferien, eigene Tippfehler bis zum
  Ende des Zählers, ein geänderter Fingerabdruck (Abschnitt 12). Darum die Frist grosszügig wählen, den Zähler nicht
  zu knapp und das Vernichtungs-Passwort deutlich anders als das Master-Passwort.

## 12. Aussperr-Risiken und Wege zurück

Mehr Faktoren heisst auch mehr Wege, sich selbst auszusperren. Siegel hat **keine Hintertür**, auch nicht für den
Entwickler: Was hier als verloren steht, ist verloren.

| Was passiert | Folge | Weg zurück |
|---|---|---|
| Master-Passwort vergessen | Tresor öffnet nicht | Sperrbildschirm → «Notfallcode verwenden» (Stufen 4/5: zwei der drei Teile) → neues Master-Passwort. Danach Stufe 1, alle Einträge Schutz 1, vernichtbare Einträge weg |
| Fingerabdruck hinzugefügt oder entfernt | Alle Touch-ID-Schlüssel des Tresors unbrauchbar: ab Stufe 2 öffnet der Tresor nicht, Einträge ab Schutz 2 lassen sich nicht aufdecken, **vernichtbare Einträge sind endgültig verloren** | Notfallcode. Vorher: Notfallkit bereitlegen, Selbstvernichtung ausschalten (abwählen), wenn die markierten Einträge bleiben sollen |
| Touch ID gesperrt (zu viele Fehlversuche) | vorübergehend | Mac mit dem Passwort entsperren (z. B. ⌃⌘Q und neu anmelden), «Erneut versuchen» |
| Deckel zu, Tastatur mit Touch ID nicht verbunden | vorübergehend | Deckel öffnen bzw. Tastatur verbinden, «Erneut versuchen» |
| Schlüsseldatei in `Hardware/` gelöscht | wie geänderter Fingerabdruck | Notfallcode |
| Mac defekt, gestohlen, neu aufgesetzt, neuer Mac (auch mit Migrationsassistent) | Die Secure Enclave des alten Macs ist weg | Sicherung vom zweiten Ort + Stufe 1: Master-Passwort; ab Stufe 2: Notfallcode bzw. zwei Teile («Aus Sicherung wiederherstellen…»). **Ohne Sicherung ausserhalb des Macs ist der Tresor verloren** |
| Container aus Time Machine zurückgeholt | Schlüsseldateien sind vom Backup ausgenommen (seit v4.3) und fehlen | ab Stufe 2: Notfallcode |
| QR-Karte verloren oder gesehen worden | Tresor öffnet nicht (Stufen 4/5); Einträge ab Schutz 4 nicht aufdeckbar. Wer die Karte findet oder fotografiert hat, hat einen Faktor | Notfallweg (setzt Stufe und alle Faktoren zurück), danach die Stufe mit einer neuen Karte einrichten. Das ist der verlässliche Weg zu einer neuen Karte |
| Kamera defekt oder verweigert | kein Scan | «Code von der Karte abtippen» |
| Sicherheitsschlüssel verloren oder zurückgesetzt | Tresor öffnet nicht (Stufe 5); Einträge mit Schutz 5 nicht aufdeckbar | Notfallweg, danach neuen Schlüssel einrichten |
| Ein Teil des Notfallkits verloren | noch kein Schaden (zwei reichen) | sofort «Neues Notfallkit…», solange du den Tresor öffnen kannst |
| Zwei Teile bzw. das ganze Notfallkit verloren | kein Notfallweg mehr | sofort «Neues Notfallkit…». Fällt danach noch Passwort oder Faktor weg, ist der Tresor verloren |
| Passwort **und** Notfallkit verloren (oder Faktor **und** Notfallkit) | Tresor verloren | keiner |
| Selbstvernichtung ausgelöst (auch versehentlich) | markierte Einträge endgültig weg, der Rest bleibt | keiner für die markierten Einträge; Passwörter dort bei den Diensten zurücksetzen |
| Zu wenig Arbeitsspeicher (Profil Stark 2 GiB, mit Vernichtungs-Passwort das Doppelte) | Entsperren scheitert mit Hinweis | andere Programme schliessen; im Notfallweg mit Profil Standard wiederherstellen |
| Tresordatei beschädigt | öffnet nicht | «Neueste lesbare Sicherung öffnen», «Sicherung aus Datei einspielen…» oder Notfallcode über die Sicherungen |
| Tresordatei fehlt | «Tresor fehlt» | Sicherung wählen (Master-Passwort der Sicherung), sonst Notfallcode |

Vorsorge, die fast alle Fälle abdeckt:

1. Notfallkit bestätigen, sicher und getrennt aufbewahren, ab und zu mit «Notfallcode prüfen…» testen.
2. Einen zweiten Sicherungsort einrichten (USB-Stick), damit es eine Sicherung ausserhalb des Macs gibt.
3. Vor dem Ändern von Fingerabdrücken, vor einem Mac-Wechsel und vor dem Neuaufsetzen das Notfallkit bereitlegen; wer
   vernichtbare Einträge behalten will, schaltet vorher die Selbstvernichtung aus.
4. Karte und Sicherheitsschlüssel wie das Notfallkit getrennt vom Mac aufbewahren, aber nicht am selben Ort wie das
   Notfallkit.
5. Selbstvernichtung und Stufe 5 zuerst mit einem Testtresor ausprobieren (`PRUEFLISTE.md` Teil A).

## 13. Prüfe deinen Mac

| Prüfung | Wie | Was tun |
|---|---|---|
| FileVault | `fdesetup status` oder Systemeinstellungen → Datenschutz & Sicherheit | einschalten (Abschnitt 7, FileVault) |
| Mac-Analysedaten teilen | Systemeinstellungen → Datenschutz & Sicherheit → Analyse & Verbesserungen | ausschalten (Abschnitt 7, Absturzberichte) |
| Programme, die den Mac fernsteuern können | Systemeinstellungen → Datenschutz & Sicherheit → Bedienungshilfen / Bildschirmaufnahme | vor deren Einsatz Siegel sperren |
| Sidecar, AirPlay, Bildschirmspiegelung | – | Verdeckung greift bei externen Bildschirmen; beim Spiegeln vorher sperren |
| Time Machine / Cloud-Kopien | – | nach einem Passwort- oder Stufenwechsel alte Kopien bedenken |
| Handprüfungen mit echter Hardware | `PRUEFLISTE.md` | zuerst mit einem Testtresor |
