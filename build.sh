#!/bin/bash
# Baut Siegel.app (SPEC §9, §21): Grep-Sperren, swift build -c release, Bundle mit Icon, ad-hoc-Signatur mit
# Hardened Runtime und App Sandbox (genau sechs Entitlements), Prüfungen, Installation nach ~/Applications/Siegel.app.
#
# Aufruf:  ./build.sh         bauen, prüfen, installieren
#          ./build.sh run     danach starten
#
# Testziel: SIEGEL_INSTALL_DIR=/anderer/Ordner ./build.sh installiert dorthin statt nach ~/Applications. Dann wird
# eine laufende Siegel-Instanz nicht beendet, nichts bei LaunchServices angemeldet und `run` abgelehnt (die
# Testkopie hätte dieselbe Bundle-ID und damit denselben Sandbox-Container wie die echte App).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer

MODUS="${1:-}"
case "$MODUS" in
    ""|run) ;;
    *) echo "Aufruf: ./build.sh [run]" >&2; exit 2 ;;
esac

NAME="Siegel"
BUNDLE_ID="com.aralim.siegel"
BUILD="$ROOT/build"
STAGE="$BUILD/$NAME.app"
STANDARD_ORDNER="$HOME/Applications"
ZIEL_ORDNER="${SIEGEL_INSTALL_DIR:-$STANDARD_ORDNER}"
ZIEL_ORDNER="${ZIEL_ORDNER%/}"
ZIEL="$ZIEL_ORDNER/$NAME.app"
ENTITLEMENTS="$ROOT/skripte/Siegel.entitlements"
INFO_PLIST="$ROOT/skripte/Info.plist"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
# Genau diese sechs (SPEC §6 + §21), alphabetisch
SOLL_ENTITLEMENTS="com.apple.security.app-sandbox=true
com.apple.security.device.camera=true
com.apple.security.device.usb=true
com.apple.security.files.bookmarks.app-scope=true
com.apple.security.files.user-selected.read-write=true
com.apple.security.print=true"
ANZAHL_ENTITLEMENTS=6
# Genau diese Schlüssel in Info.plist (keine unerwarteten Ausnahmen), alphabetisch
SOLL_INFO_SCHLUESSEL="CFBundleDevelopmentRegion CFBundleDisplayName CFBundleExecutable CFBundleIconFile CFBundleIconName \
CFBundleIdentifier CFBundleInfoDictionaryVersion CFBundleLocalizations CFBundleName CFBundlePackageType \
CFBundleShortVersionString CFBundleSupportedPlatforms CFBundleVersion LSApplicationCategoryType LSMinimumSystemVersion \
NSCameraUsageDescription NSHighResolutionCapable NSHumanReadableCopyright NSPrincipalClass "
KAMERA_TEXT="Siegel nutzt die Kamera nur, um deine QR-Schlüsselkarte zu lesen. Bilder werden nicht gespeichert."

schritt() {   # Spalte nach Zeichen, nicht nach Bytes ausrichten (Umlaute)
    local n
    n="$(printf '%s' "$1" | LC_ALL=en_US.UTF-8 wc -m | tr -d ' ')"
    printf '  %s%*s' "$1" $((24 - n)) ''
}
ok()      { printf 'ok%s\n' "${1:+ ($1)}"; }
fehler()  { printf '\nFEHLER: %s\n' "$*" >&2; exit 1; }
ohne_farbe() { /usr/bin/perl -pe 's/\e\[[0-9;]*m//g; s/\e\]8;;.*?\e\\//g' "$1"; }   # ANSI-Farben und Links entfernen
laeuft()  { [[ -n "$(lsappinfo find "bundleid=$BUNDLE_ID" 2>/dev/null)" ]]; }
anzeige() { if [[ "$1" == "$HOME"/* ]]; then printf '~%s' "${1#"$HOME"}"; else printf '%s' "$1"; fi; }
liste()   { (cd "$1" && ls -1A | LC_ALL=C sort | tr '\n' ' '); }   # Inhalt eines Ordners, eine Zeile

[[ "$ZIEL_ORDNER" == /* ]] || fehler "SIEGEL_INSTALL_DIR muss ein absoluter Pfad sein: $ZIEL_ORDNER"
TESTZIEL=0
[[ "$ZIEL_ORDNER" == "$STANDARD_ORDNER" ]] || TESTZIEL=1
if [[ "$TESTZIEL" == 1 && "$MODUS" == "run" ]]; then
    fehler "./build.sh run startet nur die App unter ~/Applications (eine Testkopie teilt den Sandbox-Container der echten App)"
fi

mkdir -p "$BUILD"
echo "Siegel bauen"
[[ "$TESTZIEL" == 0 ]] || echo "  Testziel: $(anzeige "$ZIEL")"

# 1. Grep-Sperren (SPEC §5); vorher der Selbsttest des Prüfers
schritt "Grep-Sperren"
selbsttest="$(skripte/grep_sperren.sh --selbsttest 2>&1)" \
    || { printf 'FEHLER\n%s\n' "$selbsttest" >&2; fehler "Selbsttest der Grep-Sperren gescheitert"; }
if ! sperren="$(skripte/grep_sperren.sh 2>&1)"; then
    printf 'FEHLER\n%s\n' "$sperren" >&2
    fehler "verbotene Muster in SiegelCore/SiegelUI/SiegelHardware/Siegel/Erweiterungen (Datei:Zeile oben)"
fi
ok "$(sed -n 's/^Grep-Sperren: \([0-9]*\) Dateien.*/\1 Dateien/p' <<<"$sperren")"

# 2. Release-Bau
schritt "swift build -c release"
start=$SECONDS
if ! swift build -c release --product "$NAME" >"$BUILD/swift-build.log" 2>&1; then
    echo "FEHLER" >&2
    ohne_farbe "$BUILD/swift-build.log" >"$BUILD/swift-build.txt"
    grep -E ':[0-9]+:[0-9]+: error:' "$BUILD/swift-build.txt" | sort -u | sed -n '1,40p' >&2 \
        || tail -40 "$BUILD/swift-build.txt" >&2
    fehler "swift build (ganzes Protokoll: build/swift-build.txt)"
fi
warnungen="$( (ohne_farbe "$BUILD/swift-build.log" | grep -E ':[0-9]+:[0-9]+: warning:' || true) | sort -u)"
anzahl_warnungen="$( [[ -z "$warnungen" ]] && echo 0 || wc -l <<<"$warnungen" | tr -d ' ')"
ok "$((SECONDS - start)) s, $anzahl_warnungen Warnungen"
[[ -z "$warnungen" ]] || head -10 <<<"$warnungen" | sed 's/^/      /'
BIN_DIR="$(swift build -c release --show-bin-path)"
[[ -x "$BIN_DIR/$NAME" ]] || fehler "Binary fehlt: $BIN_DIR/$NAME"

# 3. Bundle schnüren. Nur ausdrücklich genannte Dateien kommen hinein: keine Wildcard über den Release-Ordner,
#    dort können Ressourcenbündel eines Test-Baus liegen (Siegel_SiegelCoreTests.bundle mit den Fixtures).
#    Bekommt ein App-Ziel einmal Ressourcen, das Bündel hier mit Namen kopieren und in pruefe_app erlauben.
schritt "Bundle + Icon"
rm -rf "$STAGE"
mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources"
cp "$BIN_DIR/$NAME" "$STAGE/Contents/MacOS/$NAME"
printf 'APPL????' > "$STAGE/Contents/PkgInfo"
plutil -lint -s "$INFO_PLIST" || fehler "skripte/Info.plist ungültig"
plutil -convert xml1 -o "$STAGE/Contents/Info.plist" "$INFO_PLIST"
skripte/icon_bauen.sh "$STAGE/Contents/Resources" >/dev/null || fehler "Icon (skripte/icon_bauen.sh)"
ok

# 4. Signatur: ad-hoc, Hardened Runtime, Entitlements genau nach SPEC §6/§21
schritt "Signatur"
[[ "$(plutil -p "$ENTITLEMENTS" | sed -n 's/^ *"\([^"]*\)" => \(.*\)$/\1=\2/p' | sort)" == "$SOLL_ENTITLEMENTS" ]] \
    || fehler "skripte/Siegel.entitlements enthält nicht genau die $ANZAHL_ENTITLEMENTS Einträge aus SPEC §21"
xattr -cr "$STAGE" 2>/dev/null || true
codesign --force --options runtime --timestamp=none --entitlements "$ENTITLEMENTS" --sign - "$STAGE" \
    >"$BUILD/codesign.log" 2>&1 || { cat "$BUILD/codesign.log" >&2; fehler "codesign"; }
ok "ad-hoc"

# 5. Prüfungen (Abbruch bei jeder Abweichung)
pruefe_app() {
    local app="$1" bin="$1/Contents/MacOS/$NAME" info ent flags deps rpaths k soll ist fremd
    codesign --verify --strict --verbose=2 "$app" >"$BUILD/verify.log" 2>&1 \
        || { cat "$BUILD/verify.log" >&2; fehler "codesign --verify --strict: $app"; }

    codesign -d --entitlements - --xml "$app" >"$BUILD/entitlements.ist.plist" 2>/dev/null \
        || fehler "Entitlements nicht lesbar"
    ent="$(plutil -p "$BUILD/entitlements.ist.plist" | sed -n 's/^ *"\([^"]*\)" => \(.*\)$/\1=\2/p' | sort)"
    if grep -q 'get-task-allow' <<<"$ent"; then fehler "get-task-allow ist gesetzt (Debugger offen)"; fi
    [[ "$ent" == "$SOLL_ENTITLEMENTS" ]] \
        || fehler "Entitlements weichen von SPEC §21 ab (erwartet genau $ANZAHL_ENTITLEMENTS):"$'\n'"$ent"

    info="$(codesign -d --verbose=4 "$app" 2>&1)"
    flags="$(sed -n 's/.*flags=0x[0-9a-fA-F]*(\([^)]*\)).*/\1/p' <<<"$info")"
    [[ "$flags" == "adhoc,runtime" ]] || fehler "Signatur-Flags '$flags', erwartet 'adhoc,runtime'"
    grep -q "^Identifier=$BUNDLE_ID\$" <<<"$info" || fehler "Signatur-Identifier ist nicht $BUNDLE_ID"

    deps="$(otool -L "$bin" | tail -n +2 | awk '{print $1}')"
    if grep -Eiq 'sodium|/opt/homebrew' <<<"$deps"; then
        fehler "otool -L zeigt sodium oder /opt/homebrew:"$'\n'"$deps"
    fi
    while IFS= read -r k; do
        case "$k" in /usr/lib/*|/System/Library/*) ;; *) fehler "fremde dynamische Bibliothek: $k" ;; esac
    done <<<"$deps"
    rpaths="$(otool -l "$bin" | awk '/cmd LC_RPATH/{getline; getline; print $2}')"
    if grep -Eiq 'sodium|/opt/homebrew' <<<"$rpaths"; then fehler "LC_RPATH zeigt auf /opt/homebrew"; fi
    [[ "$(lipo -archs "$bin")" == "arm64" ]] || fehler "Binary ist nicht nur arm64"

    # Inhalt des Bündels genau (Befund #47): nichts aus Test-Bauten, keine Fixtures, keine Tresordateien
    [[ "$(liste "$app/Contents")" == "Info.plist MacOS PkgInfo Resources _CodeSignature " ]] \
        || fehler "unerwarteter Inhalt in Contents: $(liste "$app/Contents")"
    [[ "$(liste "$app/Contents/MacOS")" == "$NAME " ]] \
        || fehler "unerwarteter Inhalt in Contents/MacOS: $(liste "$app/Contents/MacOS")"
    [[ "$(liste "$app/Contents/Resources")" == "Assets.car Siegel.icns " ]] \
        || fehler "unerwarteter Inhalt in Contents/Resources: $(liste "$app/Contents/Resources")"
    fremd="$(find "$app" \( -name '*.bundle' -o -name 'Fixtures' -o -name '*.siegel' -o -type l \) -print)"
    [[ -z "$fremd" ]] || fehler "unerwartete Dateien im Bündel:"$'\n'"$fremd"
    for k in Assets.car Siegel.icns; do
        [[ -s "$app/Contents/Resources/$k" ]] || fehler "Icon leer: Contents/Resources/$k"
    done

    ist="$(plutil -p "$app/Contents/Info.plist" | sed -n 's/^  "\([^"]*\)" => .*/\1/p' | LC_ALL=C sort | tr '\n' ' ')"
    [[ "$ist" == "$SOLL_INFO_SCHLUESSEL" ]] || fehler "Info.plist hat andere Schlüssel:"$'\n'"$ist"
    for k in "CFBundleIdentifier=$BUNDLE_ID" "CFBundleName=$NAME" "CFBundleDisplayName=$NAME" \
             "CFBundleExecutable=$NAME" "CFBundlePackageType=APPL" \
             "CFBundleShortVersionString=1.0" "CFBundleVersion=1" "LSMinimumSystemVersion=26.0" \
             "LSApplicationCategoryType=public.app-category.utilities" "CFBundleIconName=Siegel" \
             "CFBundleIconFile=Siegel" "NSPrincipalClass=NSApplication" "NSHighResolutionCapable=true" \
             "NSHumanReadableCopyright=© 2026 Aralim" "NSCameraUsageDescription=$KAMERA_TEXT"; do
        soll="${k#*=}"
        ist="$(plutil -extract "${k%%=*}" raw -o - "$app/Contents/Info.plist" 2>/dev/null || true)"
        [[ "$ist" == "$soll" ]] || fehler "Info.plist ${k%%=*} = '$ist', erwartet '$soll'"
    done
}
schritt "Prüfungen"
pruefe_app "$STAGE"
ok "verify --strict, $ANZAHL_ENTITLEMENTS Entitlements, adhoc,runtime, otool -L, Bündelinhalt"

# 6. Laufende Instanz sauber beenden (Apple-Event quit, kein kill); nicht beim Testziel
# Mit offenem Sheet oder Dialog lehnt AppKit das Beenden ab (Fehler -128), ohne die App zu fragen.
if [[ "$TESTZIEL" == 0 ]] && laeuft; then
    schritt "Siegel beenden"
    antwort="$(osascript -e "tell application id \"$BUNDLE_ID\" to quit" 2>&1 || true)"
    if [[ "$antwort" == *"(-128)"* ]]; then
        fehler "Siegel hat das Beenden abgelehnt (offenes Sheet oder offener Dialog). Schliessen oder Siegel von Hand beenden, dann neu bauen."
    fi
    for _ in $(seq 1 60); do laeuft || break; sleep 0.25; done   # Speichern beim Beenden darf bis 5 s dauern
    laeuft && fehler "Siegel lässt sich nicht beenden. Von Hand beenden, dann neu bauen."
    ok
fi

# 7. Installation
schritt "Installation"
[[ "$ZIEL" == */"$NAME.app" ]] || fehler "Zielpfad unerwartet: $ZIEL"
mkdir -p "$ZIEL_ORDNER"
rm -rf "$ZIEL"
ditto "$STAGE" "$ZIEL"
pruefe_app "$ZIEL"
if [[ "$TESTZIEL" == 0 && -x "$LSREGISTER" ]]; then "$LSREGISTER" -f "$ZIEL" >/dev/null 2>&1 || true; fi
ok "$(anzeige "$ZIEL")"

# 8. Starten
if [[ "$MODUS" == "run" ]]; then
    schritt "Start"
    open "$ZIEL"
    for _ in $(seq 1 40); do laeuft && break; sleep 0.25; done
    laeuft || fehler "Siegel ist nicht gestartet"
    pid="$(lsappinfo info -only pid "$(lsappinfo find "bundleid=$BUNDLE_ID" | sed -n 1p)" | sed -n 's/.*=\([0-9]*\).*/\1/p')"
    ok "PID ${pid:-?}"
fi
echo "Fertig."
