# SiegelFuzz – Notizen (SPEC §21)

Mutationsbasierter, strukturbewusster Fuzzer ohne Fremdbibliothek. Läuft nur im Debug-Bau (`@testable` für den
DEBUG-KDF-Testschalter und die internen Parser); im Release-Bau gibt er nur einen Hinweis aus. Gebaut und gefahren
wird er über `skripte/fuzz.sh` mit Address-Sanitizer (`-sanitize=address`, ohne Globals-Instrumentierung wegen der
1-MB-Wortlisten, siehe `skripte/sanitizer.sh`).

## Ablauf

- Jedes Ziel hat einen Korpus (Saat + Eingaben mit Rückkopplung, höchstens 1000 neue). Rückkopplung: **neue Kanten**
  (SanitizerCoverage `-sanitize-coverage=edge,trace-pc-guard`, Rückrufe im C-Ziel `SiegelFuzzAbdeckung`, das selbst
  nicht instrumentiert ist) oder ein **neuer Ergebnis-Code**. libFuzzer gibt es in Apples Werkzeugkette nicht
  (`-sanitize=fuzzer` wird abgelehnt), darum dieser eigene Weg. Ohne die Abdeckungs-Flags (normaler Debug-Bau) bleibt
  nur die Rückkopplung über Ergebnis-Codes. Jede Eingabe ist eine Bytefolge mit zielspezifischer Rahmung, damit sie bei
  Absturz, Hänger oder Fund gesichert und mit `skripte/fuzz.sh --wiederholen <datei> <ziel>` erneut eingespielt werden
  kann.
- Zufall: SplitMix64 aus `--saat` (protokolliert) und dem Zielnamen; ein Lauf mit gleicher Saat, gleichem Saat-Korpus
  (`build/fuzz/saat/`) und gleicher Eingabezahl erzeugt dieselben Eingaben.
- Wächter: Signal-Handler (SIGTRAP von Swift-Laufzeitfehlern, SIGABRT auch nach einem ASan-Bericht, SIGILL, SIGFPE;
  ohne ASan auch SIGSEGV/SIGBUS) schreiben die laufende Eingabe nach `build/fuzz/funde/absturz-<ziel>-<pid>.bin`;
  ein Wächter-Thread beendet den Prozess bei Überschreiten des Zeitlimits pro Eingabe (unter ASan ×4) mit Exit 77 und
  sichert `haenger-<ziel>-<pid>.bin`. Invarianten-Verletzungen ohne Absturz werden als `fund-<ziel>-<sha>.bin/.txt`
  gesichert (Exit 1).
- Ausgabe: nur Zähler, Ergebnis-Codes (feste SiegelError-Codes), Kennungen (UUIDs, Dateinamen) und Prüfsummen, nie
  Eingaben, Passwörter oder Geheimteile.

## Saat-Tresore

`build/fuzz/saat/*.siegel` (+ `.json` mit Code bzw. Teilen; nur Testwerte): einmal über die öffentliche Schnittstelle
in einem Temp-Ordner erzeugt (Testschalter-KDF 8 KiB/t = 1, In-Memory-RollbackGuard, Ordner danach gelöscht), nie im
App-Container. Stufen 1–5, Faktoren nur für Einträge, versiegelte Einträge mit Schutz 2–5, Credential 16/48/1024 Byte,
Verlauf, gelöschter Eintrag, TOTP; dazu eine v1-Datei im Speicher gebaut. Zusätzlich die eingefrorenen Fixtures
`v1_beispiel.siegel` und `v2_beispiel.siegel` (echtes Profil 256 MiB; Argon2 einmal, danach KEK-Cache; Mutationen
mit anderen KDF-Parametern im erlaubten Bereich werden bei den Fixtures übersprungen und gezählt – die Testschalter-
Saaten decken sie ab).

**Vernichtungs-Saaten (§23)** mit fester Uhr (`TestHooks.now` = 1 792 000 000) und ganzem Tresorordner
`build/fuzz/saat/<name>.umgebung/` (Tresordatei, Sicherungen, `Hardware/`): Selbstvernichtung über
`configureDestruction(… entryFactors:)` eingerichtet. Faktoren: Software-P256 statt Secure Enclave (privater Schlüssel
roh in `Hardware/<keyID>.siegelhw`, wie `VernichtungsProvider` der Kern-Tests; fehlt die Datei, ist der Schlüssel weg),
feste q und y; keine Biometrie, keine Dialoge. Im Hardware-Ordner liegen der Eintrags-SE-Schlüssel, V und ein
Platzhalter für den Entsperr-SE-Schlüssel (darf nie verschwinden). **Jede Vernichtungs-Saat hat eigene Kennungen und
eigenes Material** (`SaatWerte.seKeyID(n)`, `entryKeyID(n)`, `vKeyID(n)`, V roh = 32 × (0x5B + n), Eintrags-Schlüssel roh
= 32 × (0x30 + n)); `v5` hat ein eigenes Master-Passwort. So entsteht beim Vertauschen „fremdes Material unter dem
richtigen Namen“ (V von B unter dem Namen von A). Beim Vorbereiten von `vernichtung` und `sicherung` wird jede
Sicherung im Tresorordner einer Vernichtungs-Saat mit dem Notfallschlüssel R geöffnet und entsiegelt
(`SaatErzeugung.sicherungenPruefen`, §23.1): keine vernichtbare Kennung darin lesbar, Selbstvernichtung fehlt oder ist
dieselbe. **Fehler im Einrichtungsweg** (`configureDestruction`, `sealDestructible`, `purgeBackups`) prägen die Saaten
nur mit `--neue-saat` (sonst kommen die Saaten vom unveränderten Code); im Ziel `vernichtung` fährt Vorgang 11 diesen
Weg aber auch selbst (Markieren mit `purgeBackups`, danach dieselbe Prüfung der Sicherungen).

| Saat | Stufe | Einstellungen | Einträge | danach |
|---|---|---|---|---|
| `v4` | 4 | Totmann 30, Zähler 20, Vernichtungs-Passwort | vernichtbar Schutz 4 ×2, nicht vernichtbar Schutz 4, dazu Schutz 1–3 | – |
| `v5` | 5 | Totmann 7, Vernichtungs-Passwort | vernichtbar Schutz 5 und 4, nicht vernichtbar Schutz 5 | – |
| `v4z` | 4 | Zähler 10 | vernichtbar / nicht vernichtbar Schutz 4 | 9 falsche Passwörter (kurz vor der Schwelle) |
| `v4t` | 4 | Totmann 7, Vernichtungs-Passwort | vernichtbar / nicht vernichtbar Schutz 4 | Totmann nach 8 Tagen: vernichtet |
| `v5x` | 5 | Totmann 365, Zähler 50, Vernichtungs-Passwort | vernichtbar Schutz 5 und 4, nicht vernichtbar | mit Vernichtungs-Passwort entsperrt: vernichtet, `rekeyPending` |

`datei`, `inhalt` und `notfall` nehmen die `.siegel`-Dateien dieser Saaten mit (Inhalt mit `destruction` und
vernichtbaren Siegeln ohne Notfall-Umschlag), `sicherung` setzt sie ein, `vernichtung` braucht die ganze Umgebung.

## Ziele, Rahmung, Invarianten

| Ziel | Rahmung | Invarianten |
|---|---|---|
| `datei` | Saat-Index ‖ Datei | Fehler nur `corruptFile`/`unsupportedVersion` (Lesen) bzw. dazu `kdfParametersOutOfRange`, `kdfFailed`, `wrongPassword`, `factorMissing`, `wrongCard` (Passwortweg), `wrongRecoveryCode` (Notfallweg); Prüfsumme zuerst (unabhängig nachgerechnet); **jede Datei ≠ Saat öffnet nie** (Passwort + Faktoren, Notfallweg mit Entsiegeln), auch mit neu berechneter Prüfsumme; nur Inhalt geändert → `corruptFile`; Kopf unverändert → Notfallweg nie `wrongRecoveryCode` (§1.3) |
| `inhalt` | Saat ‖ Polster-Art ‖ JSON | mit dem DEK der Saat neu verschlüsselt; Fehler nur `corruptFile`; was gelesen wird, lässt sich schreiben und ergibt beim erneuten Lesen denselben Inhalt; direkter Weg = Dateiweg (ausser vom Kopf abhängigen Codes: Stufe, Längen, `payload.destruction`); danach `UnlockedVault`, Liste, Bericht, Aufdecken (V nach Kennung: Vernichtungs-Saaten mit V, schon vernichtete ohne), Notfallweg mit Entsiegeln und Stufe 1 ohne Absturz; unveränderte Saat: alles aufdeckbar, vernichtete Einträge genau mit `factorUnavailable(.secureEnclave)`. **Vernichtungs-Saaten zusätzlich durch den Store** (Tresorordner der Saat mit dieser Tresordatei, echtes Entsperren mit Vermerk, Kapseln der Ablage, Rotation): ausser `zustand.json` und der Ablage des Inhalts ändert sich im Hardware-Ordner nichts, gelöscht wird höchstens die alte Ablage, und keine Schlüssel-Datei (V, Eintrags-, Entsperr-SE-Schlüssel) wird überschrieben; gezielte Mutation: Ablage-Kennung bzw. V heisst wie eine Schlüssel-Datei |
| `notfall` | Art ‖ Saat ‖ Erwartung ‖ Text(e) | Fehler nur `invalidRecoveryCodeFormat`, `recoveryCodeChecksum`, `wrongRecoveryCode`; angenommene Eingaben entsprechen nach unabhängiger Normalisierung genau dem Code; ≤ 2 ersetzte Zeichen, ein Nachbartausch oder ≤ 4 „?“ (pro Teil) werden immer gefunden, mit genau den geänderten Stellen; Treffer ergeben die pk des Kopfes |
| `karte` | Erwartung ‖ q ‖ Text | Fehler nur `invalidRecoveryCodeFormat`; angenommen nur, was normalisiert dem Code von q entspricht; fremde Kartenversionen nie; harmlos umgeschriebene Karten immer |
| `csv` | Art ‖ CSV bzw. Zufall | Fehler nur `csvInvalid` mit festem Code und Zeile in der Datei; Ergebnis hält alle Grenzen (Felder, keine Steuer-/Richtungszeichen, created ≤ modified, Bericht, gültiges TOTP); Export → Import Feld für Feld gleich |
| `totp` | Art ‖ Zeitpunkt ‖ Text bzw. Zufall | Fehler nur `totpInvalid` mit festem Code; Grenzen; Code hat genau `digits` Ziffern, 1 ≤ Rest ≤ Periode für jeden Zeitpunkt (±∞, NaN, vor 1970); selbst gebaute URI ergibt genau ihre Parameter |
| `cbor` | Art ‖ Bytes | kein Absturz trotz Tiefe/Anzahl/Längen; angenommene Kodierung ist kanonisch (Rundlauf); getInfo/authenticatorData/COSE; FIDO-Fehler nach aussen nur `factorUnavailable(.securityKey)`, `factorCancelled`, `crypto("fido.input")` |
| `ctaphid` | Art ‖ Steuerbytes | Reassembler mit Rohpaketen; Zerlegen ↔ Zusammensetzen; ganze Abläufe `register`/`secret` gegen ein Gerät mit Störungen (CBOR, Rohbytes, Pakete, Stille, Busy, Keepalive); Fristen halten; ungestört genau HMAC(credRandom, Salz); Fehler nach aussen nur `factorUnavailable`/`factorCancelled`. **Abbruch** (Art 4–7, `SecurityKeyCancellation`): das Token wird beim n-ten Ereignis gesetzt (vor dem Start, KEEPALIVE, Antwortpaket, Senden, Stille, Empfang) bzw. aus einem zweiten Thread (Art 6: 0–50 ms nach dem Start, Art 7: 0–50 ms nachdem das Gerät schweigend auf Berührung zu warten begann); wahlweise hält das Gerät die Antwort auf makeCredential/getAssertion zurück. Invarianten s. unten |
| `hwdatei` | Art ‖ keyID ‖ Datei | Fehler nur `corruptFile("hw.…")`; angenommen nur mit gültiger Prüfsumme, erwarteter Art und keyID, bytegleich neu kodierbar |
| `sicherung` | Art ‖ Name bzw. Datensätze bzw. Saat ‖ Passwort-Art ‖ Weg ‖ Bitfehler | Namen der Sicherungen (lokal, zweiter Ort – ein frei gewählter Ordner, also fremde Dateinamen –, beschädigt) und Ausdünnung: erzeugte Namen werden genau zurückgelesen; die Ausdünnung löscht nie angeheftete und nie die älteste Sicherung, nur vorhandene, deterministisch. **Einspielen** (Art 3, alle Testschalter-Saaten, mit Vernichtungs-Saaten auch `restoreNewestReadableBackup`): nur die unveränderte Datei mit dem echten Passwort wird eingesetzt, nie als Vernichtungs-Sitzung; danach Zähler 0, Einstellungen aus dem Inhalt, Tresordatei öffnet, Einträge lesbar wie erwartet; ohne Erfolg Tresordatei und Sicherungen bytegleich; nur `wrongPassword` zählt (auch das Vernichtungs-Passwort, das dort nicht erkannt wird), an der Schwelle wird V vernichtet |
| `autofill` | Erwartung ‖ Eintrag ‖ Kennung | `AutofillMatcher`: harmlose Varianten (Pfad, Gross/Klein, Schlusspunkt, Unterdomain, Port 443, Benutzerinfo) passen immer; Phishing-Varianten (Name als Unterdomain/Pfad/Benutzerinfo/Anhängsel einer fremden Domain, http für https, anderer Port, Doppelgänger-Zeichen, `%2E`, Backslash, öffentliche Suffixe) nie |
| `vernichtung` | 0xD2 ‖ A ‖ B ‖ Zustand-Art ‖ Ablage-Art ‖ Welt (u16) ‖ n × (Vorgang, Variante, Anker, Zeit f64) ‖ zustand.json ‖ Ablage | s. unten |

### Ziel `vernichtung` (§23)

Jede Eingabe baut den Tresorordner der Vernichtungs-Saat A im Temp-Ordner nach und verändert ihn:

- `Hardware/zustand.json`: strukturbewusst (Felder entfernen, Typen tauschen, Zeiten in der Zukunft/Vergangenheit, an
  der Frist ± 1 s, ±∞/NaN/-0/1e999 als Zahl-Token, Zähler an der Schwelle, keyIDs aller Saaten – auch Entsperr- und
  Eintrags-SE-Schlüssel –, vaultID von A/B/fremd, Einstellungen ausserhalb der Bereiche, `rekeyPending`, `v`) oder
  bytenah; als Datei, fehlend, als Ordner oder Symlink (auf Tresordatei, auf V, ins Leere).
- Ablage des Vernichtungs-Passworts (`<fileID>.siegelhw`): Bitfehler je Bereich (Kopf, Salz, Prüfwert, Kapseln,
  Umschlag, Polster, Punkt, Prüfsumme), Art 0/1/3, fremde keyID, Version, Bloblänge, ungültiger/anderer Punkt, Länge;
  Prüfsumme meist neu berechnet; Zustand und Ablage von B (wahlweise mit der vaultID bzw. unter dem Namen von A).
- **Welt** (Bits): V von A fehlt; V-Datei von B dazu; V-Rohbytes von B unter dem V-Namen von A; Tresordatei mit
  Bitfehler im Inhalt (Kopf lesbar) bzw. fehlend; Rollback-Wächter kennt eine höhere Generation; Hardware-Ordner
  schreibgeschützt (`chflags uchg`: nichts anlegen, umbenennen, löschen – Inhalte bestehender Dateien lassen sich
  überschreiben; `chmod` hilft nicht, `FileIO.ensureDirectory` setzt 0700 zurück); Vernichtungs-Schicht
  (`ProtokollEraser`) vernichtet, wirft ohne zu löschen, tut still nichts oder löscht und wirft (der Rückfall des
  Kerns muss greifen); Wettlauf: der Testhaken `TestHooks.afterDuressArgon` (nach beiden Argon2, vor dem Vermerk)
  tauscht zustand.json gegen eine Fassung, die den Entsperr-SE-Schlüssel als V nennt.

Danach bis zu 12 Vorgänge. **Uhr** je Vorgang als Anker + Abstand (Anker: absolut, Frist, letzte echte Entsperrung,
letzte − 1 Tag, t0; aufgelöst zur Laufzeit aus dem Modell, also deterministisch; Abstand meist 0, ±1 ms, ±1 s, ±1 h,
±1 Tag), so trifft der Totmann die Grenze auch nach Fristen, die sich im Lauf verschieben. Entsperr-Vorgänge mit
**Faktor-Variante** (korrekt, Karte fehlt, Karte falsch, SE-Wert falsch, Sicherheitsschlüssel fehlt). Eine Sitzung
bleibt offen, bis ein Entsperren, Einspielen oder der Notfallweg folgt.

| Nr. | Vorgang |
|---|---|
| 0 | `destructionStatus()` |
| 1 | `checkDeadman(now:)` (auch ±∞, NaN, ±max) |
| 2 / 3 / 5 | Entsperren mit falschem Passwort / dem (aktuellen oder früheren) Vernichtungs-Passwort von A / dem einer anderen Saat |
| 4 / 7 | Entsperren mit dem echten Passwort / dazu `removeDestroyedEntries()` |
| 6 / 8 | `restoreNewestReadableBackup` mit falschem / Vernichtungs-Passwort |
| 9 | in der offenen Sitzung einen Eintrag speichern (offen, versiegelt, vernichtbar – in der Vernichtungs-Sitzung `io("entry.stale")`) |
| 10 | Passwortwechsel (in der Vernichtungs-Sitzung mit dem Vernichtungs-Passwort; sonst wahlweise mit falschem) |
| 11 | `configureDestruction`: Vernichtungs-Passwort ersetzen bzw. einschalten, nur Einstellungen, einen weiteren Eintrag markieren (async mit Eintrags-Faktoren aus Dateien, danach `purgeBackups`), Vernichtungs-Passwort entfernen |
| 12 | Notfallweg (`recover` mit Code bzw. zwei Teilen aus `<saat>.json`) |
| 13 | Verbotenes: in der Vernichtungs-Sitzung `configureDestruction`, Passwortwechsel (beides `wrongPassword`), `removeDestroyedEntries` (ohne Wirkung); in einer echten Sitzung Passwortwechsel mit falschem Passwort |
| 14 | Angreifer legt die Ablage vom Anfang zurück |

Zum Schluss (Schreibschutz weg, Tresordatei wieder da): echtes Entsperren öffnet immer eine echte Sitzung mit allen
Einträgen (auch denen, die eine Vernichtungs-Sitzung unsichtbar mitgeschrieben hat).

**Orakel (unabhängig nachgerechnet):** ein eigenes Modell der Abläufe aus KERN-NOTIZEN.md (Abschnitt
Selbstvernichtung) in `ZielVernichtungModell.swift`: `currentState` (vaultID-Bindung; ein Zustand, der den
Entsperr-SE-Schlüssel nennt, gilt nicht – ohne lesbare Tresordatei die Entsperr-SE-Schlüssel der eigenen
Sicherungen), Totmann (Frist in Date-Arithmetik, Uhr rückwärts −1 Tag, unbrauchbare Uhr), Zähler (nur
`wrongPassword`, Obergrenze 1 000 000, Schwelle), Vernichtungs-Passwort (Probe nach dem Totmann, erkannt über den
eigenen Prüfwert mit den KDF-Parametern des aktuellen Kopfes, Umschlag öffnet nur mit richtigen Faktoren und nur den
DEK seiner **Epoche** – jeder Zugangswechsel zählt sie hoch), echtes Entsperren (Rotation bei `rekeyPending`, nicht bei
Rollback-Verdacht; Vermerk nachführen, veraltete Ablage nur entfernen, wenn sie wirklich eine Ablage ist), jedes
Speichern (`syncDestructionAfterWrite`, gelöschte Einträge nach 30 Tagen weg), Passwortwechsel, Selbstvernichtung
einstellen (Reihenfolge der Prüfungen wie `destructionPlan`, Ersetzen/Entfernen = neuer DEK, alte Ablage weg),
Notfallweg (vernichtbare Einträge weg, Stufe 1, neue KDF-Parameter, Selbstvernichtung aus), Schreibschutz (Schreiben
scheitert still bzw. mit `io("destruction.write")`, Löschen überschreibt nur). Ob der Kern zustand.json annimmt,
entscheidet sein eigener Parser (`DestructionState.decode`, @testable); der eigene Leser (JSONSerialization, eigene
Bereichsprüfung) muss Feld für Feld dasselbe ergeben – auch bei Zahlen in anderer Schreibweise (`10.0`, `1e1`) und bei
der bekannten Nachsicht von JSONDecoder (ungültiges UTF-8 und rohe Steuerzeichen in übergangenen Werten,
`JWert.lesenWieJSONDecoder`). Es gibt keine Kandidaten und keinen „schwachen“ Modus mehr: jeder Widerspruch ist ein
Fund. Verglichen wird je Vorgang: Ergebnis bzw. Fehlercode (`corruptFile` ohne Zusatz), die Aufrufe der
Vernichtungs-Schicht (genaue Folge der keyIDs), der Inhalt des Hardware-Ordners (Namen **und** welche Dateien neu
geschrieben bzw. überschrieben wurden), `zustand.json` danach (Feld für Feld), die Tresordatei (gleich / geschrieben /
neuer Zugang mit neuem Salz), und in Sitzungen: Art, sichtbare Einträge, das Ergebnis jedes Aufdeckens (gegen die beim
Vorbereiten aufgedeckten Geheimteile), V-Freigaben, `destroyedEntries`, `destructibleEntries`, `destructionKeyID`,
`UnlockedVault.destructionStatus`, `deletedEntries` – nach jedem Vorgang in der Sitzung neu.

**Invarianten (modellfrei, zusätzlich):**

1. Kein Absturz, kein Hänger; Fehler je Vorgang nur aus festen Mengen (`checkDeadman`: keiner bzw.
   `io("destruction.write")`; Entsperren: `wrongPassword`, Faktor-Fehler, `vaultMissing`, `corruptFile`; das echte
   Passwort mit richtigen Faktoren und intakter Datei öffnet immer; Einspielen: `wrongPassword`,
   `corruptFile("backup.noneReadable")`, Faktor-Fehler; Sitzungs-Vorgänge: feste Codes).
2. Der Entsperr-SE-Schlüssel wird nie gelöscht oder verändert – auch ohne lesbare Tresordatei und nach dem
   Notfallweg; gelöscht wird im Hardware-Ordner nur, was ein Zustand nennt (feldbewusst: `vKeyID`, `duressFileID`,
   `destroyed.keyID`), V der Saaten oder eine Ablage des Inhalts.
3. Eine Vernichtungs-Sitzung öffnet nur mit Vorgang 3 und einer Ablage, die das Passwort erkennt; Tresordatei und
   Sicherungen bleiben dabei bytegleich (ebenso bei jedem Vorgang ohne Erfolg und bei Verbotenem, dort auch der
   Hardware-Ordner). In ihr verrät keine Abfrage die vernichtbaren Einträge (Differenz gegen den ungefilterten Inhalt:
   `entries`, `deletedEntries`, Bericht, Wiederverwendung, `lastModified`; `destructibleEntries`/`destroyedEntries`
   leer, Status ohne Vermerk, `destructionKeyID` = bisheriges V).
4. Nicht vernichtbare Einträge bleiben lesbar, solange der Eintrags-SE-Schlüssel da ist; vernichtbare liefern nie
   etwas ausser mit dem eigenen, unveränderten V (fremdes Material → `wrongPassword`).
5. **Vermerk ⇒ V weg:** Nach Totmann, Fehlversuch, Vernichtungs-Passwort und Einspielen ist eine als vernichtet
   vermerkte Datei weg (im schreibgeschützten Ordner überschrieben), und `DateiAnbieter` liefert für sie
   `factorUnavailable(.secureEnclave)`. Nicht nach dem echten Entsperren: Es übernimmt einen Vermerk auf V aus dem
   bisherigen Zustand auch dann, wenn `checkDeadman` ihn vorher nicht gelten liess; die nächste Prüfung löscht.
6. **Rotation entwertet alte Umschläge:** Nach jedem neuen Zugang (Rotation, Passwortwechsel, Vernichtungs-Passwort
   ersetzen/entfernen, Notfallweg) öffnet kein früherer Umschlag (Kopie der Ablage + sein Vernichtungs-Passwort +
   Faktoren, `DuressCrypto.open`) die neue Tresordatei, das Salz ist neu, und die eben geschriebene Ablage öffnet sie.
7. **Nach dem Markieren** liefert keine Sicherung im Tresorordner mit dem Notfallcode einen vernichtbaren Eintrag.

### Abbruch beim Sicherheitsschlüssel (`ctaphid`, Art 4–7)

Ungestörtes Gerät (nur Credential-Länge und PIN/UV-Protokolle gewählt), Abbruch zu einem gefuzzten Zeitpunkt:
vor dem Start → `factorCancelled` ohne ein einziges gesendetes Paket; sonst `factorCancelled` – Erfolg nur, wenn beim
Setzen des Tokens keine CBOR-Anfrage mehr offen war (die letzte Antwort war schon ausgeliefert), dann mit genau
HMAC(credRandom, Salz); nach dem Abbruch beginnt keine neue CBOR-Anfrage (keine halbe Registrierung, kein
makeCredential/getAssertion mehr); war eine Anfrage offen, folgt CTAPHID_CANCEL; der Ablauf endet innert 1 s (×4 unter
ASan). Danach liefert ein zweiter, ungestörter `secret`-Ablauf auf demselben Gerät genau das HMAC (keine Restantwort
des Abbruchs stört ihn). Art 6 setzt das Token aus einem zweiten Thread (Wettlauf, nicht deterministisch): höchstens
die eine Anfrage, die zwischen Prüfung und Senden lag, und dann mit CTAPHID_CANCEL; war die Antwort auf die offene
Anfrage beim Setzen schon unterwegs (der Kanal prüft das Token vor jedem Empfang, nicht danach), nimmt der Kanal sie
noch an – dann ist nichts mehr offen, und Erfolg bzw. ein fehlendes CTAPHID_CANCEL ist kein Fehler (die Hülle merkt
sich, ob die Antwort nach dem Setzen noch kam). Art 7: Das Gerät schweigt 1,5 s (kein KEEPALIVE; ein Empfang wartet
wirklich bis zu seinem Zeitlimit, aufgeweckt nur durch CTAPHID_CANCEL), das Token kommt 0–50 ms nach Beginn des
Wartens: Der Ablauf endet innert 0,25 s (×2 unter ASan) – das gelingt nur, wenn der Kanal das Token in
`cancelPoll`-Scheiben prüft. Mit Störungen gelten nur die allgemeinen Abbildungsregeln.

## Funde (17.10.2026, Ziel `vernichtung`, vernichtung-8 im Ziel `inhalt`)

| Befund | Ursache | Korrektur | Regressionstest |
|---|---|---|---|
| vernichtung-1 | `zustand.json` mit `vKeyID` (bzw. `destroyed.keyID`) = Entsperr-SE-Schlüssel des Kopfes: ein falsches Passwort an der Schwelle bzw. der Totmann-Schalter löschte den Entsperr-Schlüssel → Tresor nur noch mit Notfallcode | `currentState()`: ein Zustand, der den Entsperr-SE-Schlüssel nennt, gilt nicht (`DestructionState.names`) | `KernVernichtungFuzzBefundeTests.entsperrSchluesselNieVernichten` |
| vernichtung-2 | `duressFileID` im Zustand = V bzw. Eintrags-SE-Schlüssel: das **echte** Entsperren (und jedes Speichern) löschte ihn als „veraltete Ablage“ → vernichtbare Einträge still vernichtet bzw. nicht vernichtbare unlesbar | `removeStaleDuressFile`: nie Entsperr-SE-Schlüssel, Eintrags-SE-Schlüssel oder V des Inhalts | `…alteAblageNieInGebrauch` |
| vernichtung-3 | `checkDeadman(now: +∞)`: V gelöscht, Vermerk nicht schreibbar (`io("destruction.encode")`) – Besitzer sah keine Meldung | unbrauchbare Uhr (±∞, NaN) → wie rückwärts: nichts | `…uhrUnbrauchbar` |
| vernichtung-4 | Wettlauf: `recordDuressUnlock` las zustand.json nach dem Argon2 ungefiltert (`DestructionState.read`). Wurde er zwischen Probe und Vermerk gegen einen Zustand getauscht, der den Entsperr-SE-Schlüssel als V nennt, löschte der Kern ihn selbst (Testhaken `afterDuressArgon`, Welt-Bit „Wettlauf“) | über `currentState()` lesen; gilt der Zustand nicht, nichts vermerken und nichts löschen | `…wettlaufProbeUndVermerk` |
| vernichtung-5 | Hardware-Ordner nicht beschreibbar: `checkDeadman` warf `io("file.create")` statt des dokumentierten `io("destruction.write")` (V war schon überschrieben) | `DestructionState.write`/`writeAtomically`: jeder Schreibfehler → `io("destruction.write")` | `…hardwareOrdnerNichtBeschreibbar` |
| vernichtung-6 | Tresordatei fehlt (bzw. Kopf unlesbar): `currentState` nahm den Zustand ungefiltert; nannte er den Entsperr-SE-Schlüssel als V, löschten Totmann bzw. Zähler ihn – mit der Sicherung, die man dann einsetzt, öffnete der Tresor nur noch mit dem Notfallcode | ohne lesbaren Kopf gilt kein Zustand, der den Entsperr-SE-Schlüssel einer eigenen Sicherung (bzw. beiseitegelegten Tresordatei) nennt | `…ohneTresordateiNieAussperren` |
| vernichtung-7 | Notfallweg: `syncDestructionAfterWrite` mit dem neuen Kopf (Stufe 1, keine Faktoren) entfernte als „veraltete Ablage“, was `duressFileID` nannte – auch den alten Entsperr-SE-Schlüssel, den Eintrags-Schlüssel oder V, die ältere Sicherungen noch brauchen | `removeStaleDuressFile` löscht nur eine Datei, die wirklich eine Ablage mit dieser Kennung ist (`readDuressFile`) | `…notfallwegLoeschtNurAblagen` (dazu angepasst `…alteAblageNieInGebrauch`) |
| vernichtung-8 (Ziel `inhalt`) | Ein Inhalt mit eigenem, abweichendem V und der Ablage-Kennung des bisherigen V (nur über einen fehlerhaften Schreiber erreichbar; paarweise innerhalb des Inhalts verschieden): das echte Entsperren kapselte die Ablage per rename über die V-Datei | `writeDuressFile` ersetzt nur eine Datei mit der Form einer Ablage (Länge, magic, kind 2, Bloblänge 1922 – eine beschädigte oder fremde Ablage heilt weiter), sonst `io("destruction.write")` | `…ablageUeberschreibtKeinenSchluessel` |
| Tiefenverteidigung (Prüfbefund) | `checkDestruction` liess Ablage-Kennung = V bzw. Eintrags-SE-Schlüssel und V/Ablage = Entsperr-SE-Schlüssel des Kopfes zu (nur über einen fehlerhaften Schreiber erreichbar; das Kapseln hätte den Schlüssel per rename überschrieben) | paarweise verschieden (`checkDestruction`, `destructionKeysAvoid(header:)` in `decryptPayload` und `persist`) | `…schluesselKennungenVerschieden`; Fuzz: `inhalt` fährt Vernichtungs-Saaten durch `store.unlock` |

**Langlauf mit dem endgültigen Stand (17.10.2026 abends, PRUEFBERICHT.md §8):** `fuzz.sh 30 --neue-saat`, Saat
1792260436, alle 12 Ziele je 30 min (6.0 h, 57.6 Mio. Eingaben), dazu `vernichtung` dreimal, `inhalt` und
`sicherung` je einmal mit anderen Saaten (1792262286, 1792262401, 1792262402; 2.5 h): 8.5 Fuzz-Stunden, **0 Funde**,
kein Absturz, kein Hänger. `vernichtung` allein: 30 927 Eingaben in 2 h, 19 065–19 116 Kanten. Wirksamkeitsproben
danach (Totmann erst nach der Frist, kein Rückfall bei untätiger Vernichtungs-Schicht, ungefilterter Vermerk wie vor
vernichtung-4): alle drei gefunden (Selbsttest, 27 s, 1. Eingabe), Fund-Dateien in
`build/fuzz/funde/proben-20261017-langlauf/`.

## Bauen und Fahren

```bash
skripte/fuzz.sh 30                      # alle Ziele parallel, je 30 min (Saat = Unix-Zeit, protokolliert)
skripte/fuzz.sh 20 --nacheinander       # 20 min insgesamt, nach Gewicht verteilt (vernichtung 14 %)
skripte/fuzz.sh 5 --ziele vernichtung --saat 1792198534
skripte/fuzz.sh --wiederholen build/fuzz/funde/<datei>.bin <ziel>
```

Ergebnisse: `build/fuzz/lauf-<Zeit>/` (`<ziel>.json` mit Zählern und Kanten, `<ziel>.log`, `zusammenfassung.txt`).
Exit-Code 1 bei Fund, Absturz oder Hänger (bis 17.10.2026 ging er in der Subshell der Zusammenfassung verloren und
war immer 0).
`fuzz.sh` nicht ändern, während ein Lauf läuft (Bash liest Skripte stückweise; gemessen: der Lauf endete vor der
Zusammenfassung). Der Python-Differenztest `referenz/differenz.sh` nutzt `SiegelFuzz --mutanten <ordner> --anzahl N`.
Die Grep-Sperren (§5) gelten hier nicht; trotzdem keine Inhalte ausgeben. Proben (eingeschleuste Fehler) im
Einrichtungsweg der Saaten (`configureDestruction`, `sealDestructible`, `purgeBackups`, `SaatErzeugung`) wirken auf die
Saaten nur mit `--neue-saat`; danach die Saaten mit dem unveränderten Code wieder neu erzeugen. Nach `--neue-saat` passen ältere Fund-Dateien
von `vernichtung` und `sicherung` nicht mehr zur Saat (sie nennen deren Kennungen); zum Nachspielen den Saat-Ordner
des Fundlaufs verwenden. `vernichtung` ist langsam (echte Dateien mit `F_FULLFSYNC`, mehrere Argon2 pro Eingabe,
gemessen rund 9 Eingaben/s ohne ASan mit bis zu 12 Vorgängen); die Temp-Ordner `siegelfuzz-vernichtung-<pid>`,
`siegelfuzz-sicherung-<pid>` und `siegelfuzz-inhalt-<pid>` werden pro Eingabe geleert und beim Beenden entfernt
(`atexit`; nach einem Absturz bleiben sie liegen). Rahmung `vernichtung` seit Version 2 (Byte 0xD2): ältere Fund-Dateien
lassen sich nicht mehr einspielen.
