#!/bin/bash
# swift test mit Wachhund (für die CI): Hängt der Lauf länger als SIEGEL_TEST_LIMIT_MIN Minuten (Standard 20),
# werden Speicherlage und die Stacks aller Testprozesse ausgegeben, danach wird abgebrochen. So zeigt ein
# hängender CI-Lauf, WO er hängt, statt nur am Job-Zeitlimit zu sterben.
#
#   skripte/test_wachhund.sh [weitere swift-test-Argumente]
set -uo pipefail

limit_min="${SIEGEL_TEST_LIMIT_MIN:-20}"
ausgabe="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/siegel-wachhund"
mkdir -p "$ausgabe"

swift build --build-tests || exit 1

swift test --skip-build "$@" &
pid=$!
start=$(date +%s)
deadline=$(( start + limit_min * 60 ))

while kill -0 "$pid" 2>/dev/null; do
    sleep 10
    if kill -0 "$pid" 2>/dev/null && (( $(date +%s) >= deadline )); then
        echo "::error::swift test läuft seit ${limit_min} min – Speicherlage und Stacks folgen"
        echo "=== Speicher"
        memory_pressure 2>/dev/null | tail -4
        vm_stat 2>/dev/null | head -12
        echo "=== Prozesse"
        ps -axo pid,ppid,rss,%cpu,etime,command | grep -E 'xctest|swiftpm-testing-helper|PackageTests|swift-test' | grep -v grep
        for p in $(pgrep -f 'xctest|swiftpm-testing-helper|PackageTests'); do
            echo "=== Stacks von $p"
            /usr/bin/sample "$p" 3 -mayDie -file "$ausgabe/sample-$p.txt" >/dev/null 2>&1
            # Nur die Thread-Bäume, ohne die lange Bildliste am Ende.
            sed -n '/^Call graph:/,/^Total number in stack/p' "$ausgabe/sample-$p.txt" | head -600
        done
        kill "$pid" 2>/dev/null
        pkill -f 'xctest|swiftpm-testing-helper|PackageTests' 2>/dev/null
        exit 1
    fi
done

wait "$pid"
status=$?
echo "swift test: Status $status nach $(( $(date +%s) - start )) s"
exit "$status"
