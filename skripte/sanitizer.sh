#!/bin/bash
# Sanitizer-Läufe (SPEC §21): swift test mit AddressSanitizer und ThreadSanitizer, je in einem eigenen Bauordner
# (.build/sanitize-<art>), damit der normale Bau nicht neu übersetzt werden muss. Die Läufe sind nacheinander,
# weil Tests mit echten Argon2-Profilen 1–2 GiB brauchen.
#
# Aufruf:  skripte/sanitizer.sh                  beide (address, thread)
#          skripte/sanitizer.sh address           nur einer
#          skripte/sanitizer.sh thread -- --filter Shamir    weitere Argumente für swift test nach --
#
# Ergebnis: Zusammenfassung je Lauf (Tests, Fehler, Sanitizer-Meldungen), Protokolle in build/sanitizer/.
# Exit-Code 1, wenn ein Lauf scheitert oder ein Sanitizer etwas meldet.
# Hinweis: libsodium ist vorübersetzt und nicht instrumentiert; geprüft wird der Swift-Code von Siegel.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

arten=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        address|thread) arten+=("$1"); shift ;;
        --) shift; break ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "Aufruf: skripte/sanitizer.sh [address] [thread] [-- swift-test-Argumente]" >&2; exit 2 ;;
    esac
done
[[ ${#arten[@]} -gt 0 ]] || arten=(address thread)
extra=("$@")

LOGS="$ROOT/build/sanitizer"
mkdir -p "$LOGS"
# halt_on_error: bei ASan der erste Fund bricht ab (mit Stapel); TSan meldet alles und endet mit Exit-Code 66
export ASAN_OPTIONS="${ASAN_OPTIONS:-halt_on_error=1:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1}"
export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=0:second_deadlock_stack=1}"

ohne_farbe() { /usr/bin/perl -pe 's/\e\[[0-9;]*m//g' "$1"; }
zaehle() { grep -c -E "$1" "$2" || true; }

gesamt=0
echo "Siegel Sanitizer-Läufe (${arten[*]})"
for art in "${arten[@]}"; do
    log="$LOGS/$art.log"
    txt="$LOGS/$art.txt"
    printf '  %-10s' "$art"
    start=$SECONDS
    status=0
    flags=()
    # ASan ohne Globals-Instrumentierung: Die Wortlisten sind String-Literale um 1 MB; mit Redzone überschreiten sie
    # die Grenze des Linkers (ld: „Assertion failed: (name.size() <= maxLength)“, gemessen mit Xcode 27).
    # Heap, Stack und use-after-return bleiben geprüft.
    [[ "$art" != "address" ]] || flags=(-Xswiftc -Xllvm -Xswiftc -asan-globals=0)
    # Laufzeitgrenzen der Tests strecken (ASan ≈ 6×, TSan ≈ 10–20× langsamer, dazu parallele Tests); ohne Sanitizer
    # gelten sie unverändert (Tests/SiegelCoreTests/SanitizerHilfe.swift). Exit-Tests schalten sich selbst ab.
    faktor=12
    [[ "$art" != "thread" ]] || faktor=30
    SIEGEL_ZEITFAKTOR="${SIEGEL_ZEITFAKTOR:-$faktor}" \
    swift test --sanitize="$art" --scratch-path "$ROOT/.build/sanitize-$art" ${flags[@]+"${flags[@]}"} \
        ${extra[@]+"${extra[@]}"} >"$log" 2>&1 || status=$?
    ohne_farbe "$log" >"$txt"
    dauer=$((SECONDS - start))

    # swift-testing meldet je Testziel „Test run with N tests in M suites passed/failed …“ (SiegelCoreTests und
    # SiegelHardwareTests): alle Läufe zusammenzählen, dazu die übersprungenen (manuelle Tests, Exit-Test).
    lauf="$(grep -E 'Test run with [0-9]+ tests? in [0-9]+ suites? (passed|failed)' "$txt" \
        | sed -E 's/^.*Test run with ([0-9]+) tests? in ([0-9]+) suites? (passed|failed).*/\1 \2 \3/' \
        | awk '{ t += $1; s += $2; if ($3 == "failed") f = 1 }
               END { if (NR > 0) printf "%d Tests in %d Suiten %s (%d Testziele)", t, s, (f ? "mit Fehlern" : "bestanden"), NR }' \
        || true)"
    uebersprungen="$(zaehle '➜ Test .* skipped' "$txt")"
    [[ -z "$lauf" || "$uebersprungen" -eq 0 ]] || lauf="$lauf, $uebersprungen übersprungen"
    # ohne die Gesamtzeile „✘ Test run with … failed after …“
    fehlgeschlagen="$(grep -E '✘ Test .* failed after' "$txt" | grep -vc 'Test run with' || true)"
    asan="$(zaehle 'ERROR: AddressSanitizer' "$txt")"
    tsan="$(zaehle 'WARNING: ThreadSanitizer' "$txt")"
    ubsan="$(zaehle 'runtime error:' "$txt")"
    meldungen=$((asan + tsan + ubsan))

    if [[ $status -eq 0 && $meldungen -eq 0 ]]; then
        printf 'ok    %4d s  %s\n' "$dauer" "${lauf:-(keine Testzusammenfassung gefunden)}"
    else
        gesamt=1
        printf 'FEHLER %3d s  Exit %d, %s Tests gescheitert, Meldungen: ASan %s, TSan %s, UBSan %s\n' \
            "$dauer" "$status" "$fehlgeschlagen" "$asan" "$tsan" "$ubsan"
        [[ -z "$lauf" ]] || printf '               %s\n' "$lauf"
        # Kurzfassung der Funde: Art und Ort jeder Sanitizer-Meldung (ohne PID und Adressen), gescheiterte Tests
        grep -E '^SUMMARY: (Address|Thread|UndefinedBehavior)Sanitizer|ERROR: AddressSanitizer:|WARNING: ThreadSanitizer:|runtime error:' "$txt" \
            | sed -E 's/^==[0-9]+==//; s/ on address 0x[0-9a-f]+.*//; s/ \(pid=[0-9]+\)//' | cut -c1-160 \
            | sort | uniq -c | sort -rn | sed -n '1,15p' | sed 's/^/               /' || true
        grep -E '✘ Test .* (failed after|recorded an issue)' "$txt" | sed -n '1,15p' | sed 's/^/               /' || true
        if [[ $meldungen -eq 0 && -z "$lauf" ]]; then
            grep -E 'error:' "$txt" | sort -u | sed -n '1,15p' | sed 's/^/               /' || true
        fi
        printf '               Protokoll: %s\n' "${txt#"$ROOT/"}"
    fi
done
exit $gesamt
