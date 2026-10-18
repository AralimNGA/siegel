#!/usr/bin/env python3
"""Siegel – Logo-Entwurf 03 «Schlüssel-S»: baut mark.svg + icon.svg und rendert die PNGs.

Konstruktion (Einheit u, Scheibe = 21 u Durchmesser):
  - senkrecht fünf Streifen 5-3-5-3-5: drei schwarze Bänder (5 u), zwei Schlitze (3 u)
  - Schlitze enden in Kreisen mit Ø 5 u (= Bandstärke) -> liegende Schlüssellöcher, Schlitz:Kreis = 3:5
  - Kreismitten bei (−3 u, −4 u) und (+3 u, +4 u): 3-4-5-Dreieck, Abstand zur Mitte genau 5 u,
    dadurch bleibt zwischen Schlüsselloch und Scheibenrand überall mindestens ein Ring von 3 u
  - punktsymmetrisch; oberer Schlitz von rechts, unterer von links -> das Schwarz ist ein S

Aufruf:  python3 bauen.py            (SVGs schreiben, PNGs rendern, falls der Renderer da ist)
Renderer: Umgebungsvariable SVG_RENDER oder der Standardpfad unten.
"""
import math
import os
import subprocess

HIER = os.path.dirname(os.path.abspath(__file__))
RENDER = os.environ.get(
    "SVG_RENDER",
    "/private/tmp/claude-501/-Users-aralim-Desktop/b9cbdf41-db59-4539-9e1d-f81d64e2d90a/scratchpad/svg_render",
)


def zahl(v):
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


class Pfad:
    def __init__(self):
        self.d, self.cur = [], None

    def M(self, x, y):
        self.d.append(f"M{zahl(x)} {zahl(y)}")
        self.cur = (x, y)

    def L(self, x, y):
        cx, cy = self.cur
        if abs(cy - y) < 1e-9:
            self.d.append(f"H{zahl(x)}")
        elif abs(cx - x) < 1e-9:
            self.d.append(f"V{zahl(y)}")
        else:
            self.d.append(f"L{zahl(x)} {zahl(y)}")
        self.cur = (x, y)

    def C(self, *p):
        self.d.append("C" + " ".join(zahl(v) for v in p))
        self.cur = (p[4], p[5])

    def bogen(self, mx, my, r, a0, a1):
        """Kreisbogen um (mx,my) von Winkel a0 nach a1 in Grad (a1 > a0: im Uhrzeigersinn).
        In Stücke <= 90 Grad geteilt, damit die SVG-Flags eindeutig sind."""
        n = max(1, math.ceil(abs(a1 - a0) / 90 - 1e-9))
        for i in range(1, n + 1):
            a = math.radians(a0 + (a1 - a0) * i / n)
            x, y = mx + r * math.cos(a), my + r * math.sin(a)
            self.d.append(f"A{zahl(r)} {zahl(r)} 0 0 {1 if a1 > a0 else 0} {zahl(x)} {zahl(y)}")
            self.cur = (x, y)

    def Z(self):
        self.d.append("Z")

    def __str__(self):
        return "".join(self.d)


def schluessel_s(u, cx=512.0, cy=512.0):
    """Kontur des Zeichens als ein einziger geschlossener Pfad."""
    R = 10.5 * u          # Scheibe
    h = 1.5 * u           # halbe Schlitzhöhe
    rk = 2.5 * u          # Schlüssellochkreis
    ax, ay = cx - 3 * u, cy - 4 * u      # oberes Schlüsselloch (links)
    bx, by = cx + 3 * u, cy + 4 * u      # unteres Schlüsselloch (rechts)
    phi = math.degrees(math.asin(h / rk))  # Ansatz Schlitz am Kreis (36.87° – wieder 3-4-5)
    k = math.cos(math.radians(phi)) * rk   # = 2 u

    def rand_x(y, seite):
        return cx + seite * math.sqrt(R * R - (y - cy) ** 2)

    def winkel(x, y):
        return math.degrees(math.atan2(y - cy, x - cx)) % 360

    p = Pfad()
    p.M(cx, cy - R)
    # Scheibe oben -> rechter Einlauf oberer Schlitz
    y = ay - h
    p.bogen(cx, cy, R, 270, winkel(rand_x(y, 1), y))
    p.L(ax + k, y)
    p.bogen(ax, ay, rk, -phi, -360 + phi)          # Schlüsselloch oben, gegen den Uhrzeigersinn
    y = ay + h
    p.L(rand_x(y, 1), y)
    y2 = by + h
    p.bogen(cx, cy, R, winkel(rand_x(y, 1), y) - 360, winkel(rand_x(y2, -1), y2))
    p.L(bx - k, y2)
    p.bogen(bx, by, rk, 180 - phi, -180 + phi)      # Schlüsselloch unten
    y = by - h
    p.L(rand_x(y, -1), y)
    p.bogen(cx, cy, R, winkel(rand_x(y, -1), y), 270)
    p.Z()
    return str(p)


def squircle(x, y, s, r):
    """Quadrat mit kontinuierlicher Krümmung an den Ecken (Apple-Rundung, Bézier-Näherung)."""
    a, b, c, d, e, g, hh = [v * r for v in
                            (1.52866483, 1.08849323, 0.86840689, 0.66993427, 0.06549600, 0.37196778, 0.16496403)]
    X0, Y0, X1, Y1 = x, y, x + s, y + s
    p = Pfad()
    p.M(X0 + a, Y0)
    p.L(X1 - a, Y0)
    p.C(X1 - b, Y0, X1 - c, Y0, X1 - d, Y0 + e)
    p.C(X1 - g, Y0 + hh, X1 - hh, Y0 + g, X1 - e, Y0 + d)
    p.C(X1, Y0 + c, X1, Y0 + b, X1, Y0 + a)
    p.L(X1, Y1 - a)
    p.C(X1, Y1 - b, X1, Y1 - c, X1 - e, Y1 - d)
    p.C(X1 - hh, Y1 - g, X1 - g, Y1 - hh, X1 - d, Y1 - e)
    p.C(X1 - c, Y1, X1 - b, Y1, X1 - a, Y1)
    p.L(X0 + a, Y1)
    p.C(X0 + b, Y1, X0 + c, Y1, X0 + d, Y1 - e)
    p.C(X0 + g, Y1 - hh, X0 + hh, Y1 - g, X0 + e, Y1 - d)
    p.C(X0, Y1 - c, X0, Y1 - b, X0, Y1 - a)
    p.L(X0, Y0 + a)
    p.C(X0, Y0 + b, X0, Y0 + c, X0 + e, Y0 + d)
    p.C(X0 + hh, Y0 + g, X0 + g, Y0 + hh, X0 + d, Y0 + e)
    p.C(X0 + c, Y0, X0 + b, Y0, X0 + a, Y0)
    p.Z()
    return str(p)


# ---- Parameter -------------------------------------------------------------------------------
U_MARKE = 36          # Scheibe 756 px = 74 % der Fläche
U_ICON = 23           # Scheibe 483 px = 58.6 % des Körpers (824); Schlitze liegen bei 16 px fast genau auf Pixelzeilen 6 und 9
KOERPER = (100, 100, 824, 185)
SCHATTEN = dict(lagen=12, wachsen=1.5, dy0=4.0, dy=1.25, deckkraft=0.014)


def schatten():
    x, y, s, r = KOERPER
    out = []
    S = SCHATTEN
    for i in range(S["lagen"], 0, -1):
        g = i * S["wachsen"]
        dy = S["dy0"] + i * S["dy"]
        out.append(f'  <path d="{squircle(x - g, y - g + dy, s + 2 * g, r + g)}" fill="#000" '
                   f'fill-opacity="{S["deckkraft"]}"/>')
    return "\n".join(out)


def mark_svg():
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">\n'
            f'  <path d="{schluessel_s(U_MARKE)}" fill="#000"/>\n'
            '</svg>\n')


def icon_svg():
    x, y, s, r = KOERPER
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">\n'
            f'{schatten()}\n'
            f'  <path d="{squircle(x, y, s, r)}" fill="#fff"/>\n'
            f'  <path d="{schluessel_s(U_ICON)}" fill="#000"/>\n'
            '</svg>\n')


def rendern(svg, png, px, bg):
    subprocess.run([RENDER, os.path.join(HIER, svg), os.path.join(HIER, png), str(px), bg],
                   check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    open(os.path.join(HIER, "mark.svg"), "w").write(mark_svg())
    open(os.path.join(HIER, "icon.svg"), "w").write(icon_svg())
    if os.path.exists(RENDER):
        for px in (1024, 128, 32, 16):
            rendern("icon.svg", f"icon-{px}.png", px, "#EDEDED")
        rendern("mark.svg", "mark-512.png", 512, "white")
        print("SVGs und PNGs geschrieben:", HIER)
    else:
        print("SVGs geschrieben; Renderer fehlt:", RENDER)
