#!/bin/bash
# Fuzzer SiegelFuzz (SPEC §21): Debug-Bau mit Address-Sanitizer, alle Ziele parallel (oder nacheinander), mit
# protokollierter Saat. Jedes Ziel prüft seine Invarianten (kein Absturz, kein Hänger, manipulierte Dateien öffnen
# nie, Fehler sind feste SiegelError-Codes) und sichert jede auffällige Eingabe in build/fuzz/funde/.
#
# Aufruf:  skripte/fuzz.sh <Minuten>                        alle Ziele gleichzeitig, je <Minuten> lang
#          skripte/fuzz.sh <Minuten> --nacheinander         <Minuten> insgesamt, nach Gewicht auf die Ziele verteilt
#          skripte/fuzz.sh <Minuten> --ziele datei,notfall  nur diese Ziele
#          skripte/fuzz.sh <Minuten> --saat 12345           feste Saat (Standard: Unix-Zeit, wird protokolliert)
#          skripte/fuzz.sh <Minuten> --weiter               nach einem Fund weiterfuzzen (sonst Abbruch des Ziels)
#          skripte/fuzz.sh <Minuten> --neue-saat            Saat-Tresore neu erzeugen (sonst build/fuzz/saat/);
#                                                           eingeschleuste Fehler im Einrichtungsweg der Saaten
#                                                           (configureDestruction, purgeBackups, SaatErzeugung)
#                                                           wirken nur damit – danach mit dem unveränderten Code
#                                                           erneut --neue-saat
#          skripte/fuzz.sh --wiederholen <datei> <ziel>     gesicherte Eingabe einmal einspielen (Reproduktion)
#
# Ziele: datei inhalt notfall karte csv totp cbor ctaphid hwdatei sicherung autofill vernichtung
#        (Beschreibung: Sources/SiegelFuzz/FUZZ-NOTIZEN.md)
# Ergebnis: build/fuzz/lauf-<Zeit>/ mit je Ziel <ziel>.json (Zähler) und <ziel>.log, dazu zusammenfassung.txt.
# Exit-Code 1 bei Fund, Absturz oder Hänger; 2 bei Bau- oder Aufruffehler.
#
# Saat-Tresore entstehen nur im Temp-Ordner mit dem DEBUG-KDF-Testschalter (8 KiB, t = 1) und In-Memory-
# RollbackGuard; nie im App-Container. Ausgaben enthalten keine Eingaben oder Geheimnisse, nur Codes und Zähler.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

SCRATCH="$ROOT/.build/fuzz-asan"
ARBEIT="$ROOT/build/fuzz"
FUNDE="$ARBEIT/funde"
FLAGS=(-Xswiftc -sanitize=address -Xswiftc -Xllvm -Xswiftc -asan-globals=0
       -Xswiftc -sanitize-coverage=edge,trace-pc-guard)
ALLE=(datei inhalt notfall karte csv totp cbor ctaphid hwdatei sicherung autofill vernichtung)

# Gewichte für --nacheinander (Summe 100): Dateiformat und Inhalt zuerst, teure Notfall-Korrektur und die
# Selbstvernichtung (langsam: echte Dateien, mehrere Argon2 pro Eingabe) genug Zeit.
gewicht() {
    case "$1" in
        datei) echo 20 ;; vernichtung) echo 14 ;; inhalt) echo 13 ;; notfall) echo 13 ;; ctaphid) echo 9 ;;
        csv) echo 8 ;; cbor) echo 7 ;; totp) echo 6 ;; hwdatei) echo 3 ;; sicherung) echo 3 ;; karte) echo 2 ;;
        autofill) echo 2 ;; *) echo 5 ;;
    esac
}

bauen() {
    mkdir -p "$ARBEIT"
    echo "Bau: swift build -c debug --product SiegelFuzz -Xswiftc -sanitize=address (ohne Globals-Instrumentierung),"
    echo "     -sanitize-coverage=edge,trace-pc-guard"
    # -asan-globals=0: die Wortlisten (String-Literale um 1 MB) sprengen sonst mit Redzone die Symbolgrenze von ld
    # („Assertion failed: (name.size() <= maxLength)“, gemessen mit Xcode 27). Heap, Stack, use-after-return bleiben.
    # -sanitize-coverage: Kanten-Abdeckung als Rückkopplung (Rückrufe in Sources/SiegelFuzzAbdeckung); libFuzzer
    # (-sanitize=fuzzer) liefert Apples Werkzeugkette nicht mit.
    # Geänderte Flags machen den Bauordner nicht zuverlässig ungültig (gemessen: alte Objekte wurden weiterverwendet),
    # darum bei anderen Flags neu bauen.
    if [[ "$(cat "$SCRATCH/.siegel-flags" 2>/dev/null || true)" != "${FLAGS[*]}" ]]; then
        rm -rf "$SCRATCH"
        mkdir -p "$SCRATCH"
        printf '%s' "${FLAGS[*]}" >"$SCRATCH/.siegel-flags"
    fi
    if ! swift build -c debug --product SiegelFuzz --scratch-path "$SCRATCH" "${FLAGS[@]}" >"$ARBEIT/bau.log" 2>&1; then
        sed 's/\x1b\[[0-9;]*m//g' "$ARBEIT/bau.log" | grep -E 'error' | sort -u | head -20 >&2
        echo "Bau gescheitert (Protokoll: build/fuzz/bau.log)" >&2
        exit 2
    fi
    BIN="$(swift build -c debug --scratch-path "$SCRATCH" --show-bin-path "${FLAGS[@]}")/SiegelFuzz"
    if [[ ! -x "$BIN" ]]; then BIN="$(find "$SCRATCH" -name SiegelFuzz -type f -perm -u+x | head -1)"; fi
    otool -L "$BIN" | grep -q asan || { echo "SiegelFuzz ohne ASan gebaut?" >&2; exit 2; }
}

# ASan: erster Fund bricht mit Bericht ab (abort → der Fuzzer sichert die Eingabe); Lecks prüft ASan auf macOS nicht.
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:halt_on_error=1:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:print_summary=1}"

if [[ "${1:-}" == "--wiederholen" ]]; then
    [[ $# -eq 3 ]] || { echo "Aufruf: skripte/fuzz.sh --wiederholen <datei> <ziel>" >&2; exit 2; }
    bauen
    exec "$BIN" --wiederholen "$2" --ziel "$3" --wurzel "$ROOT" --arbeitsordner "$ARBEIT"
fi

[[ $# -ge 1 && "$1" =~ ^[0-9]+([.][0-9]+)?$ ]] || { sed -n '2,20p' "$0"; exit 2; }
MINUTEN="$1"; shift
SAAT="$(date +%s)"
ZIELE=("${ALLE[@]}")
NACHEINANDER=0
EXTRA=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --saat) SAAT="$2"; shift 2 ;;
        --ziele) IFS=',' read -r -a ZIELE <<<"$2"; shift 2 ;;
        --nacheinander) NACHEINANDER=1; shift ;;
        --weiter|--neue-saat) EXTRA+=("$1"); shift ;;
        *) echo "unbekannt: $1" >&2; exit 2 ;;
    esac
done

bauen
LAUF="$ARBEIT/lauf-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LAUF" "$FUNDE"
SUMME="$LAUF/zusammenfassung.txt"
{
    echo "SiegelFuzz-Lauf $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Saat: $SAAT   Minuten: $MINUTEN   Modus: $([[ $NACHEINANDER -eq 1 ]] && echo nacheinander || echo parallel)"
    echo "Ziele: ${ZIELE[*]}"
    echo "Binärdatei: ${BIN#"$ROOT/"} (SHA-256 $(shasum -a 256 "$BIN" | cut -c1-16)…)"
    echo "ASAN_OPTIONS: $ASAN_OPTIONS"
} | tee "$SUMME"

# Saat-Tresore einmal erzeugen (sonst würden parallele Ziele gleichzeitig schreiben) und protokollieren.
"$BIN" --ziel datei --sekunden 0 --max-eingaben 0 --saat "$SAAT" --wurzel "$ROOT" --arbeitsordner "$ARBEIT" \
    ${EXTRA[@]+"${EXTRA[@]}"} >"$LAUF/saat.log" 2>&1 || { cat "$LAUF/saat.log" >&2; echo "Saat-Erzeugung gescheitert" >&2; exit 1; }
EXTRA_OHNE_NEU=()
for x in ${EXTRA[@]+"${EXTRA[@]}"}; do [[ "$x" == "--neue-saat" ]] || EXTRA_OHNE_NEU+=("$x"); done
{
    echo "Saat-Korpus (build/fuzz/saat):"
    (cd "$ARBEIT/saat" && shasum -a 256 *.siegel | awk '{ printf "  %s  %s…\n", $2, substr($1, 1, 16) }')
} | tee -a "$SUMME"

# Ein Ziel fahren; Hartgrenze = Laufzeit + 5 Minuten (der Fuzzer hat zusätzlich sein Zeitlimit pro Eingabe).
fahre() {
    local ziel="$1" sekunden="$2"
    local grenze=$(( ${sekunden%.*} + 300 ))
    local status=0
    /usr/bin/perl -e 'alarm shift; exec @ARGV' "$grenze" \
        "$BIN" --ziel "$ziel" --sekunden "$sekunden" --saat "$SAAT" --wurzel "$ROOT" --arbeitsordner "$ARBEIT" \
        ${EXTRA_OHNE_NEU[@]+"${EXTRA_OHNE_NEU[@]}"} >"$LAUF/$ziel.json" 2>"$LAUF/$ziel.log" || status=$?
    echo "$status" >"$LAUF/$ziel.exit"
}

START=$SECONDS
if [[ $NACHEINANDER -eq 1 ]]; then
    summe=0
    for z in "${ZIELE[@]}"; do summe=$((summe + $(gewicht "$z"))); done
    for z in "${ZIELE[@]}"; do
        s=$(/usr/bin/perl -e "printf '%.0f', $MINUTEN * 60 * $(gewicht "$z") / $summe")
        echo "  $z: $s s"
        fahre "$z" "$s"
    done
else
    echo "Alle Ziele parallel, je $MINUTEN min …"
    for z in "${ZIELE[@]}"; do fahre "$z" "$(/usr/bin/perl -e "printf '%.0f', $MINUTEN * 60")" & done
    wait
fi
DAUER=$((SECONDS - START))

# Zusammenfassung. Der Exit-Code wird vor der Ausgabe bestimmt: Zuweisungen im Block unten laufen in der Subshell
# der Pipe (| tee) und gingen verloren (gemessen: Exit 0 trotz Fund).
gesamt=0
for z in "${ZIELE[@]}"; do
    [[ "$(cat "$LAUF/$z.exit" 2>/dev/null || echo '?')" == "0" ]] || gesamt=1
done
{
    echo
    printf '%-11s %9s %12s %9s %8s %15s %6s %6s  %s\n' Ziel Sekunden Eingaben "pro s" Arten "Kanten (neu)" Funde Exit Bemerkung
    for z in "${ZIELE[@]}"; do
        exitcode="$(cat "$LAUF/$z.exit" 2>/dev/null || echo '?')"
        zeile="$(grep -E '^\{' "$LAUF/$z.json" | tail -1 || true)"
        bemerkung=""
        case "$exitcode" in
            0) ;; 1) bemerkung="Fund"; gesamt=1 ;; 77) bemerkung="HÄNGER"; gesamt=1 ;;
            142) bemerkung="Hartgrenze (alarm)"; gesamt=1 ;; *) bemerkung="ABSTURZ (Exit $exitcode)"; gesamt=1 ;;
        esac
        if [[ -n "$zeile" ]]; then
            /usr/bin/python3 - "$zeile" "$z" "$exitcode" "$bemerkung" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
kanten = "%d (+%d)" % (d.get("kantenEnde", 0), d.get("kantenEnde", 0) - d.get("kantenNachVorbereitung", 0))
print(f"{sys.argv[2]:<11} {d.get('sekunden', 0):9.0f} {d.get('eingaben', 0):12d} {d.get('proSekunde', 0):9.0f} "
      f"{d.get('ergebnisArten', 0):8d} {kanten:>15} {len(d.get('funde', [])):6d} {sys.argv[3]:>6}  {sys.argv[4]}")
PY
        else
            printf '%-11s %9s %12s %9s %8s %15s %6s %6s  %s\n' "$z" - - - - - - "$exitcode" "$bemerkung"
        fi
    done
    echo
    echo "Wanduhr: ${DAUER} s"
    ls "$FUNDE" 2>/dev/null | grep -E '^(absturz|haenger|fund)-' | sed 's/^/Fund-Datei: build\/fuzz\/funde\//' || true
} | tee -a "$SUMME"
if [[ $gesamt -ne 0 ]]; then
    echo "Auffälligkeiten – Protokolle in ${LAUF#"$ROOT/"}/, Reproduktion: skripte/fuzz.sh --wiederholen <datei> <ziel>"
fi
exit $gesamt
