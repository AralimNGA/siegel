#!/bin/bash
# Gegenprobe (SPEC §21): Die unabhängige Python-Referenz öffnet die festen Beispieldateien und vergleicht mit den
# Werten aus Tests/SiegelCoreTests/Fixtures/README.md (und für v1 zusätzlich mit erwartet_v1_beispiel.json).
# Dazu eine Manipulationsprobe: gekippte Bytes müssen scheitern – mit und ohne neu berechnete Prüfsumme.
#
#   referenz/gegenprobe.sh            # aus dem Paketordner oder von überall
#
# v2_beispiel.siegel wird geprüft, sobald die Datei existiert. Dann braucht README.md einen Abschnitt, dessen
# Überschrift `v2_beispiel.siegel` nennt, mit den Zeilen `| Master-Passwort | `…` |` und je nach Faktormaske
# `| Faktor Secure Enclave (Hex) | `…` |`, `| Faktor Karte (Hex) | `…` |`, `| Faktor FIDO2 (Hex) | `…` |`.
# Optional verglichen: Formatversion, vaultID, Kit-Kennung, Generation, Grösse.
#
# Dazu die Interop-Dateien des C#-Kerns (windows/SPEC-WINDOWS.md W7) aus windows/tests/Fixtures/ mit den Werten aus
# deren README.md (Faktor-Zeilen dort: Name beginnt mit „Faktor Secure Enclave“, „Faktor Karte“, „Faktor FIDO2“):
# Kopf, Passwortweg, Inhalt (Einträge, Siegel, Windows-Hello-Art), Manipulation, falsches Passwort.
#
# Umgebung: SIEGEL_PYTHON (Standard: Python 3.12 von python.org), SIEGEL_LIBSODIUM (Standard: Homebrew).
# Exit 0 = alles stimmt, 1 = Abweichung, 2 = Werkzeug fehlt.
set -euo pipefail

HIER="$(cd "$(dirname "$0")" && pwd)"
PAKET="$(cd "$HIER/.." && pwd)"
PY="${SIEGEL_PYTHON:-/Library/Frameworks/Python.framework/Versions/3.12/bin/python3}"
SODIUM="${SIEGEL_LIBSODIUM:-/opt/homebrew/opt/libsodium/lib/libsodium.dylib}"

[[ -x "$PY" ]] || { echo "Python fehlt: $PY (SIEGEL_PYTHON setzen)" >&2; exit 2; }
[[ -f "$SODIUM" ]] || { echo "libsodium fehlt: $SODIUM (SIEGEL_LIBSODIUM setzen)" >&2; exit 2; }
export SIEGEL_LIBSODIUM="$SODIUM"

exec "$PY" -I - "$HIER/siegel_referenz.py" "$PAKET/Tests/SiegelCoreTests/Fixtures" "$HIER" "$PAKET/windows/tests/Fixtures" <<'PYTHON'
import json, os, re, subprocess, sys, hashlib

referenz, fixtures, hier, cs_fixtures = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
fehler = []


def lauf(art, pfad_oder_daten, passwort, faktoren=(), nur_kopf=False):
    """Startet die Referenz; Daten (bytes) gehen über eine Temp-Datei im Fixture-freien Temp-Ordner."""
    argumente = [sys.executable, "-I", referenz, art, pfad_oder_daten] + list(faktoren)
    if nur_kopf:
        argumente.append("--nur-kopf")
    p = subprocess.run(argumente, input=passwort.encode("utf-8"), capture_output=True, timeout=120)
    if p.returncode == 0:
        return json.loads(p.stdout.decode("utf-8")), None
    return None, p.stderr.decode("utf-8").strip()


def abschnitt(readme, dateiname):
    """Text vom Abschnitt, dessen Überschrift den Dateinamen nennt, bis zur nächsten ##-Überschrift."""
    teile = re.split(r"(?m)^## ", readme)
    for teil in teile:
        kopfzeile = teil.split("\n", 1)[0]
        if dateiname in kopfzeile:
            return teil
    return None


def zeile(text, name):
    m = re.search(r"(?m)^\|\s*" + re.escape(name) + r"\s*\|\s*`([^`]*)`[^|`]*\|", text)
    if m:
        return m.group(1)
    m = re.search(r"(?m)^\|\s*" + re.escape(name) + r"\s*\|\s*([^|]*?)\s*\|", text)
    return m.group(1) if m else None


def pruefe(bedingung, text):
    print(("  ok    " if bedingung else "  FEHLT ") + text)
    if not bedingung:
        fehler.append(text)


readme = open(os.path.join(fixtures, "README.md"), encoding="utf-8").read()

for version in (1, 2):
    name = "v%d_beispiel.siegel" % version
    pfad = os.path.join(fixtures, name)
    if not os.path.exists(pfad):
        print("%s: nicht vorhanden – übersprungen" % name)
        continue
    print("%s:" % name)
    text = abschnitt(readme, name)
    if text is None:
        pruefe(False, "Abschnitt in README.md")
        continue
    passwort = zeile(text, "Master-Passwort")
    if passwort is None:
        pruefe(False, "Master-Passwort in README.md")
        continue
    faktoren = []
    for zeilenname, option in (("Faktor Secure Enclave (Hex)", "--se"), ("Faktor Karte (Hex)", "--karte"),
                               ("Faktor FIDO2 (Hex)", "--fido")):
        wert = zeile(text, zeilenname)
        if wert:
            faktoren += [option, wert]

    ergebnis, meldung = lauf("siegel", pfad, passwort, faktoren)
    pruefe(ergebnis is not None, "öffnet mit dem Passwort aus README.md" + ("" if ergebnis else " (" + str(meldung) + ")"))
    if ergebnis is None:
        continue
    pruefe(ergebnis["formatVersion"] == version, "Formatversion %d" % version)
    vergleiche = (("vaultID", "vaultID", str), ("Kit-Kennung", "kitID", str), ("Generation", "generation", int),
                  ("Grösse", "dateigroesse", lambda s: int(re.sub(r"\D", "", s.split("Byte")[0]))))
    for zeilenname, schluessel, umwandeln in vergleiche:
        wert = zeile(text, zeilenname)
        if wert:
            pruefe(ergebnis[schluessel] == umwandeln(wert), "%s = %s" % (zeilenname, wert))
    sha = zeile(text, "SHA-256 der Datei")
    if sha:
        pruefe(hashlib.sha256(open(pfad, "rb").read()).hexdigest() == sha, "SHA-256 der Datei")

    erwartet_pfad = os.path.join(hier, "erwartet_v%d_beispiel.json" % version)
    if os.path.exists(erwartet_pfad):
        erwartet = json.load(open(erwartet_pfad, encoding="utf-8"))
        for schluessel in ("vaultID", "kitID", "generation", "dateigroesse", "kdf", "factorMask", "recoveryScheme"):
            pruefe(ergebnis[schluessel] == erwartet[schluessel], "%s wie erwartet" % schluessel)
        inhalt = ergebnis["inhalt"]
        pruefe((inhalt.get("recoveryConfirmedAt") is not None) == erwartet["notfallkitBestaetigt"], "Notfallkit bestätigt")
        eintraege = [e for e in inhalt["entries"] if e.get("deletedAt") is None]
        pruefe(len(eintraege) == len(erwartet["eintraege"]), "%d Einträge" % len(erwartet["eintraege"]))
        for ist, soll in zip(eintraege, erwartet["eintraege"]):
            for feld in ("title", "username", "password", "url", "notes", "totp"):
                if feld in soll:
                    pruefe(ist[feld] == soll[feld], "%s: %s" % (soll["title"], feld))
            pruefe([h["password"] for h in ist["history"]] == soll["verlauf"], "%s: Verlauf" % soll["title"])
            for stueck in soll.get("notesEnthaelt", []):
                pruefe(stueck in ist["notes"], "%s: Notiz enthält %r" % (soll["title"], stueck))

    # Manipulation: gekippte Bytes (a) ohne und (b) mit neu berechneter Prüfsumme dürfen nie öffnen.
    original = open(pfad, "rb").read()
    import tempfile
    with tempfile.TemporaryDirectory() as ordner:
        probe = os.path.join(ordner, "probe.siegel")
        label = ("Siegel v%d file check" % version).encode("ascii")
        stellen = [8, 30, 200, 1700, 3000, 3420, len(original) // 2, len(original) - 40, len(original) - 1]
        for stelle in stellen:
            daten = bytearray(original)
            daten[stelle] ^= 0x01
            open(probe, "wb").write(bytes(daten))
            _, meldung = lauf("siegel", probe, passwort, faktoren)
            pruefe(meldung is not None and "file.checksum" in meldung, "Byte %d gekippt → file.checksum" % stelle)
            if stelle < len(original) - 32:
                daten = daten[:-32] + hashlib.sha3_256(label + bytes(daten[:-32])).digest()
                open(probe, "wb").write(bytes(daten))
                ergebnis2, meldung = lauf("siegel", probe, passwort, faktoren)
                pruefe(ergebnis2 is None, "Byte %d gekippt + Prüfsumme neu → abgelehnt (%s)" % (stelle, meldung))
        open(probe, "wb").write(original[:-1])
        pruefe(lauf("siegel", probe, passwort, faktoren)[0] is None, "gekürzte Datei → abgelehnt")
        open(probe, "wb").write(original + b"\0")
        pruefe(lauf("siegel", probe, passwort, faktoren)[0] is None, "verlängerte Datei → abgelehnt")

    _, meldung = lauf("siegel", pfad, passwort + "x", faktoren)
    pruefe(meldung is not None and "wrongPassword" in meldung, "falsches Passwort → wrongPassword")

# Interop-Dateien des C#-Kerns (SPEC-WINDOWS W7): Name, Anzahl Einträge, Windows-Hello-Art?
def zeile_beginnt(text, praefix):
    m = re.search(r"(?m)^\|\s*" + re.escape(praefix) + r"[^|]*\|\s*`([^`]*)`[^|`]*\|", text)
    return m.group(1) if m else None


cs_readme_pfad = os.path.join(cs_fixtures, "README.md")
cs_readme = open(cs_readme_pfad, encoding="utf-8").read() if os.path.exists(cs_readme_pfad) else ""
for name, anzahl, hello in (("cs_v2_stufe_a.siegel", 3, False), ("cs_v2_beispiel.siegel", 6, False),
                            ("cs_v2_hello.siegel", 6, True)):
    pfad = os.path.join(cs_fixtures, name)
    if not os.path.exists(pfad):
        print("%s: nicht vorhanden – übersprungen" % name)
        continue
    print("%s (C#):" % name)
    text = abschnitt(cs_readme, "`" + name + "`")
    passwort = zeile(text, "Master-Passwort") if text else None
    if passwort is None:
        pruefe(False, "Abschnitt mit Master-Passwort in windows/tests/Fixtures/README.md")
        continue
    faktoren = []
    for praefix, option in (("Faktor Secure Enclave", "--se"), ("Faktor Karte", "--karte"), ("Faktor FIDO2", "--fido")):
        wert = zeile_beginnt(text, praefix)
        if wert:
            faktoren += [option, wert]
    kopf, meldung = lauf("siegel", pfad, "", nur_kopf=True)
    pruefe(kopf is not None, "Kopf lesbar" + ("" if kopf else " (" + str(meldung) + ")"))
    if kopf is None:
        continue
    benoetigt = {"--se": 1, "--karte": 2, "--fido": 4}
    faktoren = [x for i, x in enumerate(faktoren) if benoetigt[faktoren[i - i % 2]] & kopf["factorMask"]]
    ergebnis, meldung = lauf("siegel", pfad, passwort, faktoren)
    pruefe(ergebnis is not None, "öffnet mit Passwort und Faktoren aus README.md" + ("" if ergebnis else " (" + str(meldung) + ")"))
    if ergebnis is None:
        continue
    pruefe(ergebnis["formatVersion"] == 2, "Formatversion 2")
    for zeilenname, schluessel, umwandeln in (("vaultID", "vaultID", str), ("Kit-Kennung", "kitID", str),
                                              ("Generation", "generation", int),
                                              ("Grösse", "dateigroesse", lambda s: int(re.sub(r"\D", "", s.split("Byte")[0])))):
        wert = zeile(text, zeilenname)
        if wert:
            pruefe(ergebnis[schluessel] == umwandeln(wert), "%s = %s" % (zeilenname, wert))
    sha = zeile(text, "SHA-256 der Datei")
    pruefe(sha is not None and hashlib.sha256(open(pfad, "rb").read()).hexdigest() == sha, "SHA-256 der Datei")
    inhalt = ergebnis["inhalt"]
    eintraege = inhalt["entries"]
    pruefe(len(eintraege) == anzahl, "%d Einträge" % anzahl)
    pruefe(eintraege[0]["title"] == "Bibliothek Bern" and eintraege[0]["password"] == "Buecher-Regal-42!",
           "offener Eintrag „Bibliothek Bern“ im Klartext")
    versiegelt = [e for e in eintraege if e.get("sealed")]
    pruefe(all(e["password"] == "" and e["protection"] >= 2 for e in versiegelt), "versiegelte Einträge ohne Klartext")
    faktoren_inhalt = inhalt.get("factors", {})
    if hello:
        pruefe(faktoren_inhalt.get("windowsHello", {}).get("version") == 1 and faktoren_inhalt.get("secureEnclave") is None,
               "Eintrags-Gerätefaktor der Windows-Hello-Art")
        bloecke = [e["sealed"]["blob"] for e in versiegelt] + [g["anchor"] for g in inhalt.get("recoveryGroups", [])]
        pruefe(len(versiegelt) == 5 and all(b.get("se") is None and len(b.get("hello", {}).get("salt", "")) == 44
                                            for b in bloecke), "alle Siegel mit „hello“ statt „se“")
    else:
        pruefe("windowsHello" not in faktoren_inhalt, "keine Windows-Hello-Art")
    original = open(pfad, "rb").read()
    import tempfile
    with tempfile.TemporaryDirectory() as ordner:
        probe = os.path.join(ordner, "probe.siegel")
        for stelle in (8, 1000, len(original) // 2, len(original) - 1):
            daten = bytearray(original)
            daten[stelle] ^= 0x01
            open(probe, "wb").write(bytes(daten))
            _, meldung = lauf("siegel", probe, passwort, faktoren)
            pruefe(meldung is not None and "file.checksum" in meldung, "Byte %d gekippt → file.checksum" % stelle)
    _, meldung = lauf("siegel", pfad, passwort + "x", faktoren)
    pruefe(meldung is not None and "wrongPassword" in meldung, "falsches Passwort → wrongPassword")

print("Gegenprobe: " + ("alles stimmt" if not fehler else "%d Abweichung(en)" % len(fehler)))
sys.exit(1 if fehler else 0)
PYTHON
