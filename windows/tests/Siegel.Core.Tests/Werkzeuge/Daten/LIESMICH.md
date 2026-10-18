# Testdaten der Werkzeuge (Swift-Referenzwerte)

Erzeugt, nie von Hand ändern. Alles deterministisch (feste Saat, gzip mit mtime 0); die Erwartungswerte rechnet die
Swift-Referenz (`Sources/SiegelStaerkeExport`, Debug-Bau), nicht C#.

| Datei | Inhalt | Erzeugt von |
|---|---|---|
| `swift_kennzahlen.txt` | SHA-256 und Länge jeder Wortliste, wie Swift sie kompiliert hat; Wörterbuch-Kennzahlen, Tastaturgraphen, `MasterPasswordPolicy.userInputs` für zwei Konten | `listen_exportieren.py` |
| `staerke_korpus.txt.gz` | über 11 000 Fälle: Base64(Passwort) und Base64(Benutzereingaben) je Zeile | `korpus_erzeugen.py` |
| `staerke_erwartet.txt.gz` | je Fall Bits (17 Stellen), Stufe, Zeichenzahl, Master-Passwort-Regel; Bezugsjahr 2026 | `korpus_erzeugen.py` (Swift `bewerten`) |
| `graphem_korpus.txt.gz`, `graphem_erwartet.txt.gz` | 20 000 Zufallsfolgen aus allen Graphem-Klassen und Swifts Character-Grenzen | `korpus_erzeugen.py` (Swift `graphem`) |
| `autofill_korpus.txt.gz`, `autofill_erwartet.txt.gz` | 12 000 Paare Eintrag/Website und Swifts `AutofillMatcher.matches` | `korpus_erzeugen.py` (Swift `autofill`) |
| `titel_korpus.txt.gz`, `titel_erwartet.txt.gz` | 6 000 Adressen und Swifts CSV-Titel aus der URL | `korpus_erzeugen.py` (Swift `titel`) |
| `nfc_korpus.txt.gz`, `nfc_erwartet.txt.gz` | 69 000 Zeichenketten (jedes Zeichen der NFC-Tabelle einzeln und mit Kombinationszeichen, jedes Paar auch blockiert, Hangul-Grenzfälle, Foundation-Eigenheiten, alle Unicode-16-Zerlegungen, U+FFFE, Zufall) und Swifts `precomposedStringWithCanonicalMapping` sowie `PasswordNormalizer.normalize` | `korpus_erzeugen.py` (Swift `nfc-korpus`) |
| `gleich_korpus.txt.gz`, `gleich_erwartet.txt.gz` | 68 000 Paare (NFD/NFC-Formen, Umordnungen, Hangul, Ungleiches) und ob Swift-`String` sie für gleich hält | `korpus_erzeugen.py` (Swift `gleich`) |

Neu erzeugen (macOS mit Xcode, aus dem Paketordner):

```
python3 windows/skripte/listen_exportieren.py     # Listen, Unicode- und NFC-Tabelle, Kennzahlen
python3 windows/skripte/korpus_erzeugen.py        # Korpora und Swift-Erwartungswerte
python3 windows/skripte/korpus_erzeugen.py --pruefen && python3 windows/skripte/listen_exportieren.py --pruefen
```

Ändert sich die Swift-Schätzung, ändern sich die Erwartungswerte; der C#-Test `StaerkeKorpusTests` schlägt dann fehl,
bis C# nachgezogen ist (so ist es gewollt). Unter Windows laufen die Tests ohne Xcode, nur mit diesen Dateien.
