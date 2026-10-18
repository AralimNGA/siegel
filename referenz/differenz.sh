#!/bin/bash
# Differenztest Swift ↔ Python (SPEC §21): Der Fuzzer schreibt Mutanten der festen Beispieldateien samt Swift-Urteil
# (SiegelFuzz --mutanten), die unabhängige Python-Referenz liest jeden Mutanten selbst.
#
#   referenz/differenz.sh [Anzahl] [Saat]        # Standard: 300 Mutanten, Saat 1
#
# Geprüft:
#   - Python öffnet keinen Mutanten (Passwortweg mit den Faktoren aus Fixtures/README.md), ausser er ist bytegleich
#     mit der Beispieldatei; Swift ebenso (Urteil des Fuzzers).
#   - Struktur (Prüfsumme, Kopf, Längen): Swift `VaultFile.parse` und Python `--nur-kopf` sind sich einig. Bekannte,
#     gewollte Unterschiede werden einzeln gezählt, nicht als Abweichung: Swift ist strenger bei seKeyID = 0 mit
#     gesetztem Bit, fidoSalt = 0 mit gesetztem Bit und ctLen, das kein Vielfaches des Polsters ist; Python prüft den
#     KDF-Bereich schon beim Kopf (Swift erst vor dem Ableiten, `kdfParametersOutOfRange`).
#   - Mutanten mit anderen KDF-Parametern im erlaubten Bereich öffnet Python nicht voll (Argon2 bis 4 GiB), gezählt.
# Exit 0 = keine Abweichung, 1 = Abweichung, 2 = Werkzeug fehlt.
set -euo pipefail

HIER="$(cd "$(dirname "$0")" && pwd)"
PAKET="$(cd "$HIER/.." && pwd)"
ANZAHL="${1:-300}"
SAAT="${2:-1}"
PY="${SIEGEL_PYTHON:-/Library/Frameworks/Python.framework/Versions/3.12/bin/python3}"
SODIUM="${SIEGEL_LIBSODIUM:-/opt/homebrew/opt/libsodium/lib/libsodium.dylib}"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
[[ -x "$PY" ]] || { echo "Python fehlt: $PY (SIEGEL_PYTHON setzen)" >&2; exit 2; }
[[ -f "$SODIUM" ]] || { echo "libsodium fehlt: $SODIUM (SIEGEL_LIBSODIUM setzen)" >&2; exit 2; }
export SIEGEL_LIBSODIUM="$SODIUM"

cd "$PAKET"
swift build -c debug --product SiegelFuzz >/dev/null 2>&1 || { echo "Bau von SiegelFuzz gescheitert" >&2; exit 2; }
BIN="$(swift build -c debug --show-bin-path)/SiegelFuzz"
ORDNER="$(mktemp -d "${TMPDIR:-/tmp}/siegel-differenz.XXXXXX")"
trap 'rm -rf "$ORDNER"' EXIT
"$BIN" --mutanten "$ORDNER" --anzahl "$ANZAHL" --saat "$SAAT" --wurzel "$PAKET" >/dev/null

exec "$PY" -I - "$HIER/siegel_referenz.py" "$PAKET/Tests/SiegelCoreTests/Fixtures" "$ORDNER" <<'PYTHON'
import json, os, re, subprocess, sys
from collections import Counter

referenz, fixtures, ordner = sys.argv[1], sys.argv[2], sys.argv[3]


def zeile(text, name):
    m = re.search(r"(?m)^\|\s*" + re.escape(name) + r"\s*\|\s*`([^`]*)`[^|`]*\|", text)
    return m.group(1) if m else None


def abschnitt(readme, dateiname):
    for teil in re.split(r"(?m)^## ", readme):
        if dateiname in teil.split("\n", 1)[0]:
            return teil
    return ""


readme = open(os.path.join(fixtures, "README.md"), encoding="utf-8").read()
zugang = {}
for saat, name in (("fx1", "v1_beispiel.siegel"), ("fx2", "v2_beispiel.siegel")):
    text = abschnitt(readme, name)
    faktoren = []
    for zn, opt in (("Faktor Secure Enclave (Hex)", "--se"), ("Faktor Karte (Hex)", "--karte"), ("Faktor FIDO2 (Hex)", "--fido")):
        w = zeile(text, zn)
        if w:
            faktoren += [opt, w]
    zugang[saat] = (zeile(text, "Master-Passwort"), faktoren)


def lauf(pfad, passwort=None, faktoren=(), nur_kopf=False):
    arg = [sys.executable, "-I", referenz, "siegel", pfad] + list(faktoren) + (["--nur-kopf"] if nur_kopf else [])
    p = subprocess.run(arg, input=(passwort or "").encode("utf-8"), capture_output=True, timeout=300)
    if p.returncode == 0:
        return json.loads(p.stdout.decode("utf-8")), None
    m = re.search(r"FEHLER (\S+)", p.stderr.decode("utf-8", "replace"))
    return None, (m.group(1) if m else "absturz:" + p.stderr.decode("utf-8", "replace")[-200:])


GEWOLLT_SWIFT_STRENGER = ("header.seKeyID", "header.fidoSalt", "payload.length")
zaehler = Counter()
abweichungen = []
for z in open(os.path.join(ordner, "swift.jsonl"), encoding="utf-8"):
    m = json.loads(z)
    pfad = os.path.join(ordner, m["datei"])
    py_kopf, py_fehler = lauf(pfad, nur_kopf=True)
    swift_ok = m["swiftParse"] == "ok"
    if py_fehler and py_fehler.startswith("absturz"):
        abweichungen.append("%s: Python-Referenz abgestürzt" % m["datei"])
        continue
    if swift_ok and py_kopf is not None:
        zaehler["beide lesen"] += 1
    elif not swift_ok and py_kopf is None:
        zaehler["beide lehnen ab"] += 1
    elif not swift_ok and any(c in m["swiftParse"] for c in GEWOLLT_SWIFT_STRENGER):
        zaehler["gewollt: Swift strenger (" + m["swiftParse"] + ")"] += 1
    elif swift_ok and py_fehler == "kdfParametersOutOfRange":
        zaehler["gewollt: Python prüft KDF-Bereich im Kopf"] += 1
    else:
        abweichungen.append("%s: Swift %s, Python %s" % (m["datei"], m["swiftParse"], py_fehler or "liest"))
    if m["swift"].startswith("FUND"):
        abweichungen.append("%s: Swift-Fund %s" % (m["datei"], m["swift"]))
    if swift_ok and "pw:ok" in m["swift"] and not m["unveraendert"]:
        abweichungen.append("%s: Swift öffnet einen Mutanten" % m["datei"])
    # Voll öffnen (Passwortweg) nur mit dem Profil der Beispieldatei
    if py_kopf is not None:
        if py_kopf["kdf"] != {"opsLimit": 3, "memLimitBytes": 268435456}:
            zaehler["Python: anderes KDF-Profil, nicht voll geöffnet"] += 1
            continue
        passwort, faktoren = zugang[m["saat"]]
        voll, fehler = lauf(pfad, passwort, faktoren)
        if voll is not None and not m["unveraendert"]:
            abweichungen.append("%s: Python öffnet einen Mutanten" % m["datei"])
        elif voll is None and m["unveraendert"]:
            abweichungen.append("%s: unveränderte Beispieldatei öffnet in Python nicht (%s)" % (m["datei"], fehler))
        else:
            zaehler["Python voll: " + ("geöffnet (unverändert)" if voll else "abgelehnt " + fehler)] += 1

print("Differenztest Swift ↔ Python (%s Mutanten der Beispieldateien):" % sum(1 for _ in open(os.path.join(ordner, "swift.jsonl"))))
for k, v in sorted(zaehler.items(), key=lambda x: -x[1]):
    print("  %5d  %s" % (v, k))
for a in abweichungen:
    print("  ABWEICHUNG " + a)
print("Differenztest: " + ("keine Abweichung" if not abweichungen else "%d Abweichung(en)" % len(abweichungen)))
sys.exit(1 if abweichungen else 0)
PYTHON
