#!/usr/bin/env python3
"""Grep-Sperren für die Windows-Version (SPEC-WINDOWS W3, Gegenstück zu skripte/grep_sperren.sh auf dem Mac).

Verboten in windows/src/Siegel.Core und windows/src/Siegel.Werkzeuge (Kommentare und Zeichenketten ausgeblendet):
Console.*, Debug.Write/Print/Assert/Fail, Trace.*, Debugger.*, Environment.FailFast, `throw new X` mit einer anderen
Ausnahme als SiegelException, `XyzException.ThrowIf…`, Normalisierung über .NET/ICU (`NormalizationForm`, `IsNormalized`,
`.Normalize()`). Ausserdem unsichtbare Steuer-, Format- und Richtungszeichen
im Quelltext (Trojan Source; in Zeichenketten als \\uXXXX schreiben).

Aufruf: python3 windows/skripte/sperren_windows.py [Ordner…]   Exit 1 bei Fund (Datei:Zeile), 0 sonst.
Läuft auf macOS und Windows (nur Standardbibliothek). Der C#-Test HygieneTests prüft Siegel.Werkzeuge zusätzlich
bei jedem `dotnet test`.
"""

from __future__ import annotations

import re
import sys
import unicodedata
from pathlib import Path

WINDOWS = Path(__file__).resolve().parents[1]
STANDARD = [WINDOWS / "src" / "Siegel.Core", WINDOWS / "src" / "Siegel.Werkzeuge"]

SPERREN = [
    ("Console", re.compile(r"\bConsole\s*\.")),
    ("Debug.Write/Print/Assert/Fail", re.compile(r"\bDebug\s*\.\s*(Write|Print|Assert|Fail)")),
    ("Trace", re.compile(r"\bTrace\s*\.")),
    ("Debugger", re.compile(r"\bDebugger\s*\.")),
    ("Environment.FailFast", re.compile(r"\bEnvironment\s*\.\s*FailFast")),
    ("fremde Ausnahme", re.compile(r"\bthrow\s+new\s+(?!(?:Siegel\.Modell\.)?SiegelException\b)[\w.]+")),
    ("ThrowIf…", re.compile(r"\b\w+Exception\s*\.\s*ThrowIf")),
    # Befunde krypto-1/krypto-2: nie über .NET/ICU normalisieren (wirft bei U+FFFE, hängt an der Windows-Version);
    # NFC kommt aus der von Swift gemessenen Tabelle (Siegel.Werkzeuge/Unicode/SwiftNormalisierung.cs).
    ("ICU-Normalisierung", re.compile(r"\bNormalizationForm\b|\bIsNormalized\s*\(|\.Normalize\s*\(\s*\)")),
]
UNSICHTBAR = {"Cc", "Cf", "Zl", "Zp", "Co", "Cn"}

# Interne Ausnahmen des Kerns, die nie nach aussen gelangen (Integration Etappe 1, je Datei freigegeben). Jede andere
# Datei, die sie wirft, ist wieder ein Fund. Abgefangen werden sie hier:
# - FileIO.ExistsException („Ziel existiert schon“): in VaultStore/Typen/UnlockedVault.Schutz/DestructionState.
# - HelloMaterialNeededException (Sammelrunde der Windows-Hello-Art): nur mit HelloSealing, in UnlockedVault.Schutz.
# - CryptographicException in P256: in P256 selbst bzw. EphemeralAgreement auf feste SiegelException-Codes abgebildet.
INTERN = {
    "src/Siegel.Core/Kern/FileIO.cs": {"ExistsException"},
    "src/Siegel.Core/Kern/P256.cs": {"CryptographicException"},
    "src/Siegel.Core/Tresor/UnlockedVault.cs": {"HelloMaterialNeededException"},
    "src/Siegel.Core/Tresor/UnlockedVault.Vernichtung.cs": {"HelloMaterialNeededException"},
}
WURF = re.compile(r"\bthrow\s+new\s+([\w.]+)")


def nur_code(quelle: str) -> str:
    """Quelltext ohne Kommentare und ohne Inhalt von Zeichenketten (Zeilen bleiben erhalten)."""
    aus: list[str] = []
    i, n = 0, len(quelle)
    while i < n:
        c = quelle[i]
        if quelle.startswith("//", i):
            j = quelle.find("\n", i)
            i = n if j < 0 else j
            continue
        if quelle.startswith("/*", i):
            j = quelle.find("*/", i + 2)
            ende = n if j < 0 else j + 2
            aus.append("\n" * quelle.count("\n", i, ende))
            i = ende
            continue
        if quelle.startswith('"""', i):
            j = quelle.find('"""', i + 3)
            ende = n if j < 0 else j + 3
            aus.append('""' + "\n" * quelle.count("\n", i, ende))
            i = ende
            continue
        if c in "\"'":
            verbatim = i > 0 and quelle[i - 1] == "@"
            j = i + 1
            while j < n and quelle[j] != c and quelle[j] != "\n":
                if quelle[j] == "\\" and not verbatim:
                    j += 1
                elif verbatim and quelle[j] == '"' and j + 1 < n and quelle[j + 1] == '"':
                    j += 1
                j += 1
            aus.append(c + c)
            i = j + 1
            continue
        aus.append(c)
        i += 1
    return "".join(aus)


def pruefen(ordner: list[Path]) -> list[str]:
    funde: list[str] = []
    for basis in ordner:
        if not basis.is_dir():
            continue
        for datei in sorted(basis.rglob("*.cs")):
            if {"obj", "bin"} & set(datei.relative_to(basis).parts):
                continue
            text = datei.read_text(encoding="utf-8")
            name = datei.relative_to(WINDOWS) if datei.is_relative_to(WINDOWS) else datei
            for nummer, zeile in enumerate(text.split("\n"), 1):
                for zeichen in zeile:
                    if ord(zeichen) >= 0x80 and unicodedata.category(zeichen) in UNSICHTBAR:
                        funde.append(f"{name}:{nummer}: unsichtbares Zeichen U+{ord(zeichen):04X}")
                        break
            erlaubt = INTERN.get(str(name).replace("\\", "/"), set())
            for nummer, zeile in enumerate(nur_code(text).split("\n"), 1):
                for beschreibung, muster in SPERREN:
                    if muster.search(zeile):
                        wurf = WURF.search(zeile)
                        if beschreibung == "fremde Ausnahme" and wurf and wurf.group(1).split(".")[-1] in erlaubt:
                            continue
                        funde.append(f"{name}:{nummer}: {beschreibung}")
    return funde


def selbsttest() -> None:
    assert not SPERREN[0][1].search(nur_code('var x = "Console.WriteLine"; // Console.Write'))
    assert SPERREN[0][1].search(nur_code("/* x */ Console.WriteLine(1);"))
    assert SPERREN[5][1].search(nur_code('throw new InvalidOperationException("x");'))
    assert not SPERREN[5][1].search(nur_code('throw new SiegelException(SiegelErrorCode.Io, "x");'))
    assert not SPERREN[5][1].search(nur_code('throw new Siegel.Modell.SiegelException(SiegelErrorCode.Io, "x");'))
    assert SPERREN[5][1].search(nur_code('throw new System.InvalidOperationException();'))
    assert nur_code("a /* b\nc */ d").count("\n") == 1
    assert SPERREN[7][1].search(nur_code("text.Normalize(NormalizationForm.FormC)"))
    assert SPERREN[7][1].search(nur_code("text.Normalize()"))
    assert not SPERREN[7][1].search(nur_code('var s = "Normalize()"; // NormalizationForm'))


def main() -> int:
    selbsttest()
    ordner = [Path(a).resolve() for a in sys.argv[1:]] or STANDARD
    funde = pruefen(ordner)
    for fund in funde:
        print(fund)
    if funde:
        print(f"Grep-Sperren: {len(funde)} Fund(e)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
