#!/usr/bin/env python3
"""Prüft icon-ebene.svg am echten System-Icon: baut ein .icon (Icon Composer), übersetzt es mit actool,
lässt macOS das App-Icon zeichnen (NSWorkspace, hell und dunkel) und misst den Scheibenanteil.

Aufruf:  python3 werkzeuge/systemtest.py [--glas]     (braucht Xcode 27 und Pillow + numpy;
                                                      Python.org 3.12 hat beides)
  ohne --glas: empfohlene icon.json (Gruppe ohne Schatten und ohne Glanzkante, flach wie in der App)
  mit  --glas: Gruppe mit neutralem Schatten 0.5 und Glanzkante (Stand Plattform-Review)
Schreibt render/pruefung/system-icon[-glas].png und gibt die Messwerte aus.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HIER = os.path.dirname(os.path.abspath(__file__))
DESIGN = os.path.dirname(HIER)
ENV = dict(os.environ, DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer")
IKON_RENDER = os.path.join(HIER, "bin", "ikon_render")


def icon_json(glas):
    gruppe = {"layers": [{"image-name": "logo.svg", "name": "logo"}],
              "translucency": {"enabled": False, "value": 0.5}}
    if glas:
        gruppe["shadow"] = {"kind": "neutral", "opacity": 0.5}
    else:
        gruppe["shadow"] = {"kind": "none", "opacity": 0.5}
        gruppe["specular"] = False
    return json.dumps({"fill": {"solid": "extended-srgb:1.00000,1.00000,1.00000,1.00000"},
                       "groups": [gruppe],
                       "supported-platforms": {"squares": ["macOS"]}}, indent=2)


def main():
    glas = "--glas" in sys.argv
    from PIL import Image
    import numpy as np
    if not os.path.exists(IKON_RENDER):
        os.makedirs(os.path.dirname(IKON_RENDER), exist_ok=True)
        subprocess.run(["xcrun", "swiftc", "-O", "-o", IKON_RENDER, os.path.join(HIER, "ikon_render.swift")],
                       env=ENV, check=True)
    d = tempfile.mkdtemp(prefix="siegel-icon-")
    os.makedirs(f"{d}/Siegel.icon/Assets")
    os.makedirs(f"{d}/out")
    open(f"{d}/Siegel.icon/icon.json", "w").write(icon_json(glas))
    shutil.copy(os.path.join(DESIGN, "icon-ebene.svg"), f"{d}/Siegel.icon/Assets/logo.svg")
    subprocess.run(["xcrun", "actool", f"{d}/Siegel.icon", "--compile", f"{d}/out", "--platform", "macosx",
                    "--minimum-deployment-target", "26.0", "--app-icon", "Siegel",
                    "--output-partial-info-plist", f"{d}/out/partial.plist"],
                   env=ENV, check=True, stdout=subprocess.DEVNULL)
    # frisches Bundle mit eindeutiger ID, damit kein zwischengespeichertes Icon erscheint
    name = f"SiegelIconTest{int(time.time() * 1000) % 10**9}"
    app = f"{d}/{name}.app"
    os.makedirs(f"{app}/Contents/MacOS")
    os.makedirs(f"{app}/Contents/Resources")
    for f in ("Assets.car", "Siegel.icns"):
        shutil.copy(f"{d}/out/{f}", f"{app}/Contents/Resources/")
    open(f"{app}/Contents/MacOS/probe", "w").write("#!/bin/sh\n")
    os.chmod(f"{app}/Contents/MacOS/probe", 0o755)
    open(f"{app}/Contents/Info.plist", "w").write(
        '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
        f"<key>CFBundleIdentifier</key><string>ch.aralim.siegel.icontest.{name}</string>"
        "<key>CFBundleExecutable</key><string>probe</string><key>CFBundlePackageType</key><string>APPL</string>"
        "<key>CFBundleIconFile</key><string>Siegel</string><key>CFBundleIconName</key><string>Siegel</string>"
        "<key>LSMinimumSystemVersion</key><string>26.0</string></dict></plist>\n")
    for modus in ("hell", "dunkel"):
        subprocess.run([IKON_RENDER, app, f"{d}/{modus}", modus], check=True, stdout=subprocess.DEVNULL)

    # Messen: Körper (Deckung > 0.9 auf der Mittelzeile) und Scheibe (dunkle Pixel in der Mittelspalte)
    print("Grösse        Körper   Scheibe   Anteil")
    for f in ("16@1x", "16@2x", "32@2x", "128@2x", "512@2x"):
        a = np.array(Image.open(f"{d}/hell-{f}.png").convert("RGBA")).astype(float) / 255
        n = a.shape[0]
        c = n // 2
        koerper = (a[c, :, 3] > 0.9).sum()
        L = a[:, :, :3].mean(axis=2)
        dunkel = np.where((L[:, c] < 0.5) & (a[:, c, 3] > 0.9))[0]
        scheibe = dunkel.max() - dunkel.min() + 1
        print(f"{f:>8}  {koerper:8d} {scheibe:9d}   {scheibe / koerper * 100:5.1f} %")

    # Blatt: hell 16@1x, 16@2x, 32@2x (vergrössert), 128@2x, 512@2x-Ausschnitt; darunter dunkel
    blatt = Image.new("RGB", (5 * 266 + 10, 2 * 266 + 10), (225, 225, 230))
    for r, modus in enumerate(("hell", "dunkel")):
        grund = (225, 225, 230, 255) if modus == "hell" else (40, 40, 44, 255)
        for i, (f, px) in enumerate((("16@1x", 16), ("16@2x", 32), ("32@2x", 64), ("128@2x", 256),
                                     ("512@2x", 1024))):
            im = Image.open(f"{d}/{modus}-{f}.png").convert("RGBA")
            bg = Image.new("RGBA", im.size, grund)
            bg.alpha_composite(im)
            im = bg.convert("RGB")
            if px == 1024:
                im = im.crop((300, 300, 556, 556))
            else:
                im = im.resize((256, 256), Image.NEAREST if px < 256 else Image.LANCZOS)
            blatt.paste(im, (10 + i * 266, 10 + r * 266))
    ziel = os.path.join(DESIGN, "render", "pruefung", f"system-icon{'-glas' if glas else ''}.png")
    os.makedirs(os.path.dirname(ziel), exist_ok=True)
    blatt.save(ziel)
    shutil.rmtree(d, ignore_errors=True)
    print("geschrieben:", ziel)


if __name__ == "__main__":
    main()
