#!/bin/bash
# Autofill-Variante von Siegel bauen (SPEC §20): XcodeGen-Projekt Erweiterungen/project.yml → Siegel.app mit
# Contents/PlugIns/SiegelAutofill.appex. Das SwiftPM-Paket des Projekts ist die lokale Abhängigkeit.
#
# Aufruf:  skripte/autofill_bauen.sh
#   ohne SIEGEL_TEAM_ID              nur Kompilierprüfung (CODE_SIGNING_ALLOWED=NO): zeigt Fehler früh, ergibt
#                                    aber keine lauffähige App (ohne Signatur kein Entitlement, kein Gruppen-Container)
#   SIEGEL_TEAM_ID=ABCDE12345 …      normaler Bau mit Entwickler-Signatur. Braucht ein BEZAHLTES Apple-Entwicklerkonto:
#                                    das kostenlose Team bekommt das Entitlement autofill-credential-provider nicht
#                                    (gemessen am 16.10.2026, „Communication with Apple failed … not eligible“).
#
# Ergebnis: build/autofill/DD/Build/Products/Release/Siegel.app. Installiert nichts und fasst ~/Applications nicht an.
# Vor dem Einsatz Erweiterungen/LIESMICH.md lesen (Gruppen-Container, Umzug des Tresors, Rückweg).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

BUILD="$ROOT/build/autofill"
SPEC="$ROOT/Erweiterungen/project.yml"
PROJEKT="$ROOT/Erweiterungen/SiegelAutofill.xcodeproj"
APP="$BUILD/DD/Build/Products/Release/Siegel.app"
APPEX="$APP/Contents/PlugIns/SiegelAutofill.appex"
TEAM="${SIEGEL_TEAM_ID:-}"
GRUPPE_SUFFIX="com.aralim.siegel"
# Entitlements der Autofill-Variante: die sechs aus SPEC §21 + Gruppe + Autofill (App), drei (Erweiterung)
SOLL_APP="com.apple.developer.authentication-services.autofill-credential-provider
com.apple.developer.team-identifier
com.apple.application-identifier
com.apple.security.app-sandbox
com.apple.security.application-groups
com.apple.security.device.camera
com.apple.security.device.usb
com.apple.security.files.bookmarks.app-scope
com.apple.security.files.user-selected.read-write
com.apple.security.print"
SOLL_APPEX="com.apple.developer.authentication-services.autofill-credential-provider
com.apple.developer.team-identifier
com.apple.application-identifier
com.apple.security.app-sandbox
com.apple.security.application-groups"

schritt() {
    local n
    n="$(printf '%s' "$1" | LC_ALL=en_US.UTF-8 wc -m | tr -d ' ')"
    printf '  %s%*s' "$1" $((24 - n)) ''
}
ok()     { printf 'ok%s\n' "${1:+ ($1)}"; }
fehler() { printf '\nFEHLER: %s\n' "$*" >&2; exit 1; }
schluessel() {   # Schlüssel der Entitlements eines Bündels, sortiert
    codesign -d --entitlements - --xml "$1" 2>/dev/null >"$BUILD/ent.plist" || return 1
    plutil -p "$BUILD/ent.plist" | sed -n 's/^  "\([^"]*\)" => .*/\1/p' | LC_ALL=C sort
}

mkdir -p "$BUILD"
if [[ -z "$TEAM" ]]; then
    echo "Siegel Autofill: Kompilierprüfung (ohne SIEGEL_TEAM_ID, keine Signatur)"
else
    [[ "$TEAM" =~ ^[A-Z0-9]{10}$ ]] || fehler "SIEGEL_TEAM_ID muss eine Team-ID aus 10 Zeichen sein (A–Z, 0–9)"
    echo "Siegel Autofill: Bau mit Team $TEAM"
    echo "  Hinweis: Das geht nur mit einem bezahlten Apple-Entwicklerkonto (Apple Developer Program)."
fi

# 1. Voraussetzungen
schritt "Voraussetzungen"
command -v xcodegen >/dev/null || fehler "XcodeGen fehlt (brew install xcodegen)"
[[ -d "$DEVELOPER_DIR" ]] || fehler "Xcode nicht gefunden: $DEVELOPER_DIR"
produkte="$(swift package --package-path "$ROOT" dump-package 2>/dev/null \
    | /usr/bin/python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(sorted(p["name"] for p in d["products"] if "library" in p["type"])))')" \
    || fehler "Package.swift nicht lesbar (swift package dump-package)"
for p in SiegelCore SiegelHardware SiegelUI; do
    [[ " $produkte " == *" $p "* ]] \
        || fehler "Package.swift braucht das Bibliotheks-Produkt $p (.library(name: \"$p\", targets: [\"$p\"])), damit Xcode es einbinden kann"
done
ok "$(xcodegen --version | sed 's/Version: /XcodeGen /'), $(xcodebuild -version | head -1)"

# 2. Grep-Sperren auch für die Erweiterung (SPEC §5)
schritt "Grep-Sperren"
sperren="$(skripte/grep_sperren.sh "$ROOT/Erweiterungen/SiegelAutofill" 2>&1)" || { printf 'FEHLER\n%s\n' "$sperren" >&2; fehler "verbotene Muster in der Erweiterung"; }
ok

# 3. Xcode-Projekt erzeugen (ohne Team bleibt DEVELOPMENT_TEAM leer)
schritt "xcodegen"
SIEGEL_TEAM_ID="$TEAM" xcodegen generate --spec "$SPEC" --project "$ROOT/Erweiterungen" --quiet >"$BUILD/xcodegen.log" 2>&1 \
    || { cat "$BUILD/xcodegen.log" >&2; fehler "xcodegen"; }
ok "Erweiterungen/SiegelAutofill.xcodeproj"

# 4. Bauen
schritt "xcodebuild Release"
start=$SECONDS
args=(-project "$PROJEKT" -scheme SiegelMac -configuration Release -destination "platform=macOS,arch=arm64"
      -derivedDataPath "$BUILD/DD")
if [[ -z "$TEAM" ]]; then
    args+=(CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" DEVELOPMENT_TEAM="")
else
    args+=(-allowProvisioningUpdates DEVELOPMENT_TEAM="$TEAM")
fi
if ! xcodebuild "${args[@]}" build >"$BUILD/xcodebuild.log" 2>&1; then
    echo "FEHLER" >&2
    grep -E 'error:|not eligible|No profiles' "$BUILD/xcodebuild.log" | sort -u | sed -n '1,30p' >&2 || tail -30 "$BUILD/xcodebuild.log" >&2
    if grep -q 'not eligible\|No profiles' "$BUILD/xcodebuild.log"; then
        echo "  Das Team hat kein bezahltes Entwicklerkonto: Autofill lässt sich damit nicht signieren (SPEC §20)." >&2
    fi
    fehler "xcodebuild (ganzes Protokoll: build/autofill/xcodebuild.log)"
fi
warnungen="$(grep -E ':[0-9]+:[0-9]+: warning:' "$BUILD/xcodebuild.log" | grep -v '/SourcePackages/' | sort -u || true)"
ok "$((SECONDS - start)) s, $( [[ -z "$warnungen" ]] && echo 0 || wc -l <<<"$warnungen" | tr -d ' ') Warnungen"
[[ -z "$warnungen" ]] || head -10 <<<"$warnungen" | sed 's/^/      /'

# 5. Prüfungen
schritt "Prüfungen"
[[ -x "$APP/Contents/MacOS/Siegel" ]] || fehler "App fehlt: $APP"
[[ -x "$APPEX/Contents/MacOS/SiegelAutofill" ]] || fehler "Erweiterung fehlt: $APPEX"
[[ "$(plutil -extract NSExtension.NSExtensionPointIdentifier raw -o - "$APPEX/Contents/Info.plist")" \
    == "com.apple.authentication-services-credential-provider-ui" ]] || fehler "NSExtensionPointIdentifier falsch"
[[ "$(plutil -extract CFBundleIdentifier raw -o - "$APPEX/Contents/Info.plist")" == "com.aralim.siegel.autofill" ]] \
    || fehler "Bundle-ID der Erweiterung falsch"
gruppe="$(plutil -extract SiegelAppGroup raw -o - "$APPEX/Contents/Info.plist")"
[[ "$(lipo -archs "$APPEX/Contents/MacOS/SiegelAutofill")" == "arm64" ]] || fehler "Erweiterung ist nicht nur arm64"
for bin in "$APP/Contents/MacOS/Siegel" "$APPEX/Contents/MacOS/SiegelAutofill"; do
    if otool -L "$bin" | tail -n +2 | grep -Eiq 'sodium|/opt/homebrew'; then fehler "otool -L zeigt sodium oder /opt/homebrew: $bin"; fi
done
if [[ -z "$TEAM" ]]; then
    [[ "$gruppe" == "$GRUPPE_SUFFIX" || "$gruppe" == *".$GRUPPE_SUFFIX" ]] || fehler "SiegelAppGroup unerwartet: $gruppe"
    ok "kompiliert, unsigniert (nicht lauffähig)"
else
    [[ "$gruppe" == "$TEAM.$GRUPPE_SUFFIX" ]] || fehler "SiegelAppGroup ist '$gruppe', erwartet '$TEAM.$GRUPPE_SUFFIX'"
    codesign --verify --strict --deep "$APP" >"$BUILD/verify.log" 2>&1 || { cat "$BUILD/verify.log" >&2; fehler "codesign --verify"; }
    for paar in "$APP|$SOLL_APP" "$APPEX|$SOLL_APPEX"; do
        b="${paar%%|*}"
        ist="$(schluessel "$b")" || fehler "Entitlements nicht lesbar: $b"
        if grep -q 'get-task-allow' <<<"$ist"; then fehler "get-task-allow ist gesetzt: $b"; fi
        [[ "$ist" == "$(LC_ALL=C sort <<<"${paar#*|}")" ]] || fehler "Entitlements von $(basename "$b") weichen ab:"$'\n'"$ist"
    done
    ok "signiert, Entitlements wie erwartet"
fi
echo "Fertig: ${APP#"$ROOT/"}"
if [[ -n "$TEAM" ]]; then
    echo "Nächste Schritte (Erweiterungen/LIESMICH.md): Tresor in den Gruppen-Container umziehen, App nach /Applications,"
    echo "einmal starten, Systemeinstellungen → Allgemein → AutoFill & Passwörter → Siegel einschalten."
fi
