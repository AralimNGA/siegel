#!/usr/bin/env python3
"""Wortlisten und Unicode-Tabelle der Stärke-Schätzung für die Windows-Version (SPEC-WINDOWS W7).

Die Wortlisten haben EINE Quelle: die generierten Swift-Dateien Sources/SiegelCore/Staerke/Woerter/Liste*.swift
(selbst erzeugt von skripte/woerter/listen_bauen.py). Dieses Skript liest jedes Raw-String-Literal
`static let NAME: String = #\"\"\"…\"\"\"#` genau so, wie Swift es sieht, und schreibt es gzip-komprimiert als
eingebettete Ressource nach windows/src/Siegel.Werkzeuge/Staerke/Listen/NAME.txt.gz (deterministisch, mtime 0).

Dazu (ausser mit --ohne-swift) über das Swift-Hilfsprogramm SiegelStaerkeExport (Debug-Bau):
- `unicode`: die Unicode-Eigenschaften, mit denen Swift rechnet (Character.isLetter/isNumber/isUppercase/…,
  volle Gross-/Kleinschreibung, Graphem-Klassen aus Swifts eigenem Zerlegen) →
  windows/src/Siegel.Werkzeuge/Unicode/swift_unicode.txt.gz
- `kennzahlen`: Prüfsummen der Listen, wie Swift sie sieht, und Kennzahlen des Wörterbuchs →
  windows/tests/Siegel.Core.Tests/Werkzeuge/Daten/swift_kennzahlen.txt (der C#-Test vergleicht damit)
- `nfc`: die Normalisierung, wie Swift sie rechnet (Foundation `precomposedStringWithCanonicalMapping` gemessen,
  Gleichheit von Swift-`String`, Unicode-Alter ≤ 15.0) → windows/src/Siegel.Werkzeuge/Unicode/swift_nfc.txt.gz
  (Befunde krypto-1/2/4: der C#-Kern normalisiert nie über ICU). Gegenprobe: für jedes Zeichen aus Unicode 15.0 stimmt
  die Tabelle mit `unicodedata` dieses Pythons überein (Zerlegung, Klasse, Paare) – sonst Abbruch.

Aufruf (aus dem Paketordner oder von überall):
    python3 windows/skripte/listen_exportieren.py               alles neu schreiben
    python3 windows/skripte/listen_exportieren.py --pruefen     nur prüfen, ob die Dateien aktuell sind (Exit 1 sonst)
    python3 windows/skripte/listen_exportieren.py --ohne-swift  nur die Listen (ohne Xcode)

Nur Standardbibliothek, kein Netz.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PAKET = Path(__file__).resolve().parents[2]
QUELLE = PAKET / "Sources/SiegelCore/Staerke/Woerter"
ZIEL_LISTEN = PAKET / "windows/src/Siegel.Werkzeuge/Staerke/Listen"
ZIEL_UNICODE = PAKET / "windows/src/Siegel.Werkzeuge/Unicode/swift_unicode.txt.gz"
ZIEL_KENNZAHLEN = PAKET / "windows/tests/Siegel.Core.Tests/Werkzeuge/Daten/swift_kennzahlen.txt"
ZIEL_NFC = PAKET / "windows/src/Siegel.Werkzeuge/Unicode/swift_nfc.txt.gz"

# Alle Listen, die ZxcvbnDictionary.sources und PassphraseGenerator verwenden (Reihenfolge egal).
ERWARTET = {
    "passwords", "passwordsGerman", "englishWikipedia", "usTvAndFilm", "germanWords", "surnames", "maleNames",
    "femaleNames", "firstNamesCHDE", "surnamesCHDE", "placesCH", "passphraseWords", "englishWeb2",
}

LITERAL = re.compile(r'static let (\w+): String = #"""\n(.*?)\n([ \t]*)"""#', re.S)


def literale_lesen() -> dict[str, str]:
    """Inhalt aller Raw-String-Literale wie in Swift (mehrzeilig, Einrückung der Schlusszeile entfernt)."""
    listen: dict[str, str] = {}
    for datei in sorted(QUELLE.glob("Liste*.swift")):
        text = datei.read_text(encoding="utf-8")
        if "\r" in text:
            sys.exit(f"{datei.name}: Wagenrücklauf im Quelltext (Swift normalisiert Zeilenenden)")
        for treffer in LITERAL.finditer(text):
            name, inhalt, einzug = treffer.group(1), treffer.group(2), treffer.group(3)
            if "\\#" in inhalt:
                sys.exit(f"{datei.name}/{name}: Escape \\# im Raw-Literal wird nicht unterstützt")
            zeilen = inhalt.split("\n")
            if einzug:
                for nummer, zeile in enumerate(zeilen):
                    if zeile and not zeile.startswith(einzug):
                        sys.exit(f"{datei.name}/{name}: Zeile {nummer + 1} ist weniger eingerückt als die Schlusszeile")
                zeilen = [zeile[len(einzug):] if zeile else zeile for zeile in zeilen]
            if name in listen:
                sys.exit(f"Liste doppelt: {name}")
            listen[name] = "\n".join(zeilen)
    fehlend = ERWARTET - set(listen)
    if fehlend:
        sys.exit("Listen fehlen: " + ", ".join(sorted(fehlend)))
    return listen


def gz(daten: bytes) -> bytes:
    return gzip.compress(daten, compresslevel=9, mtime=0)


def swift_hilfsprogramm() -> Path:
    umgebung = dict(os.environ)
    umgebung.setdefault("DEVELOPER_DIR", "/Applications/Xcode.app/Contents/Developer")
    subprocess.run(["swift", "build", "--product", "SiegelStaerkeExport"], cwd=PAKET, env=umgebung, check=True,
                   stdout=subprocess.DEVNULL)
    pfad = subprocess.run(["swift", "build", "--show-bin-path"], cwd=PAKET, env=umgebung, check=True,
                          capture_output=True, text=True).stdout.strip()
    programm = Path(pfad) / "SiegelStaerkeExport"
    if not programm.is_file():
        sys.exit(f"Hilfsprogramm fehlt: {programm}")
    return programm


def swift_ausgabe(programm: Path, *argumente: str) -> bytes:
    with tempfile.TemporaryDirectory() as ordner:
        ziel = Path(ordner) / "ausgabe.txt"
        subprocess.run([str(programm), *argumente, str(ziel)], check=True)
        return ziel.read_bytes()


def soll_dateien(ohne_swift: bool) -> dict[Path, bytes]:
    listen = literale_lesen()
    dateien: dict[Path, bytes] = {}
    for name, inhalt in sorted(listen.items()):
        dateien[ZIEL_LISTEN / f"{name}.txt.gz"] = gz(inhalt.encode("utf-8"))
    if not ohne_swift:
        programm = swift_hilfsprogramm()
        dateien[ZIEL_UNICODE] = gz(swift_ausgabe(programm, "unicode"))
        kennzahlen = swift_ausgabe(programm, "kennzahlen")
        # Gegenprobe: Python liest die Literale genau so wie Swift (gleiche Prüfsummen).
        for zeile in kennzahlen.decode("utf-8").splitlines():
            teile = zeile.split()
            if len(teile) == 4 and teile[0] == "liste":
                eigen = hashlib.sha256(listen[teile[1]].encode("utf-8")).hexdigest()
                if eigen != teile[3] or str(len(listen[teile[1]].encode("utf-8"))) != teile[2]:
                    sys.exit(f"Liste {teile[1]}: Python und Swift lesen verschieden")
        dateien[ZIEL_KENNZAHLEN] = kennzahlen
        nfc = swift_ausgabe(programm, "nfc")
        nfc_gegenprobe(nfc.decode("utf-8"))
        dateien[ZIEL_NFC] = gz(nfc)
    return dateien


# Gemessen auf macOS 26.7 (18.10.2026): Foundation zerlegt U+0CCA (KANNADA VOWEL SIGN OO) in NFC nicht und setzt es aus der
# Eingabe nicht weiter zusammen (U+0CCA U+0CD5 bleibt; die Norm ergibt U+0CCB). Der C#-Kern bildet das nach.
TRAEGE_BEKANNT = {0x0CCA}


def nfc_gegenprobe(tabelle: str) -> None:
    """Für jedes Zeichen aus Unicode 15.0 (Alter aus der Tabelle) gleicht Foundation der Norm: dieselbe Zerlegung,
    Kombinationsklasse und dieselben Paare wie `unicodedata` (jede Version ab 15.0; Stabilitätsregel). Darauf beruht
    die Master-Passwort-Regel (SPEC §1.6 v4.7). Hangul-Silben stehen nicht in der Tabelle (eigene Regeln).
    Träge Zeichen (O) aus Unicode 15.0 sind ein Verhalten von Foundation, keine Datenfrage; erlaubt sind nur die
    gemessenen (TRAEGE_BEKANNT), jedes weitere bricht ab."""
    import unicodedata

    if tuple(int(x) for x in unicodedata.unidata_version.split(".")) < (15, 0, 0):
        sys.exit(f"Gegenprobe braucht unicodedata ≥ 15.0 (hier {unicodedata.unidata_version})")
    zerlegung: dict[int, list[int]] = {}
    opak: set[int] = set()
    klasse: dict[int, int] = {}
    paare: dict[tuple[int, int], int] = {}
    alt = bytearray(0x110000)
    for zeile in tabelle.splitlines():
        if not zeile or zeile.startswith("#"):
            continue
        t = zeile.split()
        werte = [int(x, 16) for x in t[1:]] if t[0] not in ("C", "SC") else [int(t[1], 16), int(t[2])]
        if t[0] in ("D", "O"):
            zerlegung[werte[0]] = werte[1:]
            if t[0] == "O":
                opak.add(werte[0])
        elif t[0] == "C":
            klasse[werte[0]] = werte[1]
        elif t[0] == "P":
            paare[(werte[0], werte[1])] = werte[2]
        elif t[0] == "A":
            for s in range(werte[0], werte[1] + 1):
                alt[s] = 1
    fehler = []
    for s in range(0x110000):
        if not alt[s] or 0xD800 <= s <= 0xDFFF or 0xAC00 <= s <= 0xD7A3:
            continue
        z = chr(s)
        nfd = [ord(c) for c in unicodedata.normalize("NFD", z)]
        if nfd != zerlegung.get(s, [s]) or (s in opak and s not in TRAEGE_BEKANNT):
            fehler.append(f"Zerlegung U+{s:04X}" + (" (träge)" if s in opak else ""))
        if s not in zerlegung and unicodedata.combining(z) != klasse.get(s, 0):
            fehler.append(f"Klasse U+{s:04X}")
        d = unicodedata.decomposition(z)
        if d and not d.startswith("<") and len(d.split()) == 2 and unicodedata.normalize("NFC", z) == z:
            a, b = (int(x, 16) for x in d.split())
            if paare.get((a, b)) != s:
                fehler.append(f"Paar U+{a:04X} U+{b:04X}")
    for (a, b), c in paare.items():
        if alt[c] and unicodedata.normalize("NFC", chr(a) + chr(b)) != chr(c):
            fehler.append(f"Paar U+{a:04X} U+{b:04X} → U+{c:04X} nicht in der Norm")
    if fehler:
        sys.exit("Foundation weicht für Zeichen aus Unicode 15.0 von der Norm ab: " + ", ".join(fehler[:20]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pruefen", action="store_true", help="nur prüfen, nichts schreiben")
    parser.add_argument("--ohne-swift", action="store_true", help="Unicode-Tabelle und Kennzahlen nicht erzeugen")
    args = parser.parse_args()

    dateien = soll_dateien(args.ohne_swift)
    veraltet = [pfad for pfad, inhalt in dateien.items() if not pfad.is_file() or pfad.read_bytes() != inhalt]
    vorhandene = {p for p in ZIEL_LISTEN.glob("*.txt.gz")}
    ueberzaehlig = sorted(vorhandene - set(dateien))
    if args.pruefen:
        for pfad in veraltet:
            print(f"veraltet: {pfad.relative_to(PAKET)}")
        for pfad in ueberzaehlig:
            print(f"überzählig: {pfad.relative_to(PAKET)}")
        return 1 if veraltet or ueberzaehlig else 0
    for pfad, inhalt in dateien.items():
        pfad.parent.mkdir(parents=True, exist_ok=True)
        if not pfad.is_file() or pfad.read_bytes() != inhalt:
            pfad.write_bytes(inhalt)
            print(f"geschrieben: {pfad.relative_to(PAKET)}")
    for pfad in ueberzaehlig:
        print(f"überzählig (bitte prüfen, nicht gelöscht): {pfad.relative_to(PAKET)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
