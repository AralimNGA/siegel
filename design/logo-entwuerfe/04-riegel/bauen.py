#!/usr/bin/env python3
"""Riegel-Logo fuer Siegel: erzeugt mark.svg und icon.svg aus exakter Geometrie.

Aufruf:  python3 bauen.py [variante]   (Standard: final)
Alle Masse im 1024er-Raster. Nur path/g/transform, keine Filter.
"""
import sys
from pathlib import Path

HIER = Path(__file__).resolve().parent
K = 0.5522847498  # Kreis-Approximation fuer 90-Grad-Boegen mit kubischen Beziers


def f(v):
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def rounded_poly(pts, radii):
    """Rechtwinkliges Polygon mit runden Ecken (Kreisbogen als kubische Bezier)."""
    n = len(pts)
    segs = []
    for i in range(n):
        p0, v, p2 = pts[i - 1], pts[i], pts[(i + 1) % n]
        r = radii[i]
        din = (v[0] - p0[0], v[1] - p0[1])
        dout = (p2[0] - v[0], p2[1] - v[1])
        lin = (din[0] ** 2 + din[1] ** 2) ** 0.5
        lout = (dout[0] ** 2 + dout[1] ** 2) ** 0.5
        din = (din[0] / lin, din[1] / lin)
        dout = (dout[0] / lout, dout[1] / lout)
        if r == 0:
            segs.append(("P", v))
            continue
        if r < 0:
            r = -r
            def Q(a, b):
                return (v[0] - din[0] * a * r + dout[0] * b * r, v[1] - din[1] * a * r + dout[1] * b * r)
            segs.append(("S", [Q(1.52866483, 0),
                               (Q(1.08849323, 0), Q(0.86840689, 0), Q(0.63149399, 0.07491100)),
                               (Q(0.37282392, 0.16905899), Q(0.16905899, 0.37282392), Q(0.07491100, 0.63149399)),
                               (Q(0, 0.86840689), Q(0, 1.08849323), Q(0, 1.52866483))]))
            continue
        a = (v[0] - din[0] * r, v[1] - din[1] * r)
        b = (v[0] + dout[0] * r, v[1] + dout[1] * r)
        c1 = (v[0] - din[0] * r * (1 - K), v[1] - din[1] * r * (1 - K))
        c2 = (v[0] + dout[0] * r * (1 - K), v[1] + dout[1] * r * (1 - K))
        segs.append(("C", a, c1, c2, b))
    out = []
    first = segs[0]
    start = {"P": lambda s: s[1], "C": lambda s: s[4], "S": lambda s: s[1][3][2]}[first[0]](first)
    out.append(f"M{f(start[0])} {f(start[1])}")
    for s in segs[1:] + [segs[0]]:
        if s[0] == "P":
            out.append(f"L{f(s[1][0])} {f(s[1][1])}")
        elif s[0] == "S":
            pts = s[1]
            out.append(f"L{f(pts[0][0])} {f(pts[0][1])}")
            for c1, c2, b in pts[1:]:
                out.append(f"C{f(c1[0])} {f(c1[1])} {f(c2[0])} {f(c2[1])} {f(b[0])} {f(b[1])}")
        else:
            _, a, c1, c2, b = s
            out.append(f"L{f(a[0])} {f(a[1])}C{f(c1[0])} {f(c1[1])} {f(c2[0])} {f(c2[1])} {f(b[0])} {f(b[1])}")
    out.append("Z")
    return "".join(out)


def squircle(x, y, w, h, r):
    """Kontinuierliche Ecke (Apple-Stil, iOS-Konstanten) als Pfad."""
    X0, Y0, X1, Y1 = x, y, x + w, y + h
    def P(px, py):
        return f"{f(px)} {f(py)}"
    d = []
    d.append(f"M{P(X0 + 1.52866483 * r, Y0)}")
    # oben rechts
    d.append(f"L{P(X1 - 1.52866471 * r, Y0)}")
    d.append(f"C{P(X1 - 1.08849323 * r, Y0)} {P(X1 - 0.86840689 * r, Y0)} {P(X1 - 0.63149399 * r, Y0 + 0.07491100 * r)}")
    d.append(f"C{P(X1 - 0.37282392 * r, Y0 + 0.16905899 * r)} {P(X1 - 0.16905899 * r, Y0 + 0.37282392 * r)} {P(X1 - 0.07491100 * r, Y0 + 0.63149399 * r)}")
    d.append(f"C{P(X1, Y0 + 0.86840689 * r)} {P(X1, Y0 + 1.08849323 * r)} {P(X1, Y0 + 1.52866471 * r)}")
    # unten rechts
    d.append(f"L{P(X1, Y1 - 1.52866471 * r)}")
    d.append(f"C{P(X1, Y1 - 1.08849323 * r)} {P(X1, Y1 - 0.86840689 * r)} {P(X1 - 0.07491100 * r, Y1 - 0.63149399 * r)}")
    d.append(f"C{P(X1 - 0.16905899 * r, Y1 - 0.37282392 * r)} {P(X1 - 0.37282392 * r, Y1 - 0.16905899 * r)} {P(X1 - 0.63149399 * r, Y1 - 0.07491100 * r)}")
    d.append(f"C{P(X1 - 0.86840689 * r, Y1)} {P(X1 - 1.08849323 * r, Y1)} {P(X1 - 1.52866471 * r, Y1)}")
    # unten links
    d.append(f"L{P(X0 + 1.52866471 * r, Y1)}")
    d.append(f"C{P(X0 + 1.08849323 * r, Y1)} {P(X0 + 0.86840689 * r, Y1)} {P(X0 + 0.63149399 * r, Y1 - 0.07491100 * r)}")
    d.append(f"C{P(X0 + 0.37282392 * r, Y1 - 0.16905899 * r)} {P(X0 + 0.16905899 * r, Y1 - 0.37282392 * r)} {P(X0 + 0.07491100 * r, Y1 - 0.63149399 * r)}")
    d.append(f"C{P(X0, Y1 - 0.86840689 * r)} {P(X0, Y1 - 1.08849323 * r)} {P(X0, Y1 - 1.52866471 * r)}")
    # oben links
    d.append(f"L{P(X0, Y0 + 1.52866471 * r)}")
    d.append(f"C{P(X0, Y0 + 1.08849323 * r)} {P(X0, Y0 + 0.86840689 * r)} {P(X0 + 0.07491100 * r, Y0 + 0.63149399 * r)}")
    d.append(f"C{P(X0 + 0.16905899 * r, Y0 + 0.37282392 * r)} {P(X0 + 0.37282392 * r, Y0 + 0.16905899 * r)} {P(X0 + 0.63149399 * r, Y0 + 0.07491100 * r)}")
    d.append(f"C{P(X0 + 0.86840689 * r, Y0)} {P(X0 + 1.08849323 * r, Y0)} {P(X0 + 1.52866483 * r, Y0)}")
    d.append("Z")
    return "".join(d)


# ---------------------------------------------------------------------------
# Varianten des Zeichens. Jede liefert eine Liste von Pfaden (schwarz).
# ---------------------------------------------------------------------------

def riegel(S=740, seam=0.56, g=0.075, h=0.27, depth=0.62, Ro=0.11, rt=0.05,
           ri=0.0, rs=0.0, tip_round=False, cy=0.5, sharp=False):
    """Quadratischer Block, durch eine Fuge konstanter Breite in Fluegel (links)
    und Rahmen (rechts) geteilt. Der Riegel des Fluegels steckt im Schliessblech.
    Alle Anteile relativ zur Kantenlaenge S."""
    X0 = 512 - S / 2
    Y0 = 512 - S / 2
    X1, Y1 = X0 + S, Y0 + S
    G = g * S
    xa = X0 + seam * S          # linke Fugenkante
    xb = xa + G                 # rechte Fugenkante
    hh = h * S
    yc = Y0 + cy * S
    yt, yb = yc - hh / 2, yc + hh / 2
    xt = xb + depth * (X1 - xb) - G  # Riegelspitze; Schliessblech-Tiefe = depth des Rahmens
    RO, RT, RI, RS = Ro * S, rt * S, ri * S, rs * S
    if tip_round:
        RT = hh / 2
    RC = 0 if sharp else RI + G   # konkave Ecken (aussen an der Fugenbiegung)
    RTG = RT if sharp else RT + G
    left = rounded_poly(
        [(X0, Y0), (xa, Y0), (xa, yt), (xt, yt), (xt, yb), (xa, yb), (xa, Y1), (X0, Y1)],
        [RO, RS, RC, RT, RT, RC, RS, RO],
    )
    right = rounded_poly(
        [(xb, Y0), (X1, Y0), (X1, Y1), (xb, Y1), (xb, yb + G), (xt + G, yb + G), (xt + G, yt - G), (xb, yt - G)],
        [RS, RO, RO, RS, RI, RTG, RTG, RI],
    )
    return [left, right]


def s_haken(S=740, g=0.075, Ro=0.11, ri=0.0, a=0.30, b=0.30):
    """Zwei ineinander greifende Haken; die Fuge beschreibt ein S."""
    X0 = 512 - S / 2
    Y0 = 512 - S / 2
    X1, Y1 = X0 + S, Y0 + S
    G = g * S
    RO, RI = Ro * S, ri * S
    # Fugen-Mittellinie: rechts y1 -> xL -> y2 -> xR -> y3 -> links
    y1 = Y0 + a * S
    y3 = Y1 - a * S
    y2 = (y1 + y3) / 2
    xL = X0 + b * S
    xR = X1 - b * S
    hg = G / 2
    pts = [(X0, Y0), (X1, Y0), (X1, y1 - hg), (xL - hg, y1 - hg), (xL - hg, y2 + hg),
           (xR - hg, y2 + hg), (xR - hg, y3 - hg), (X0, y3 - hg)]
    rad = [RO, RO, 0, RI + G, RI + G, RI, RI, 0]
    top = rounded_poly(pts, rad)
    bot = rounded_poly([(1024 - x, 1024 - y) for x, y in pts], rad)
    return [top, bot]


def querriegel(S=740, seam=0.5, g=0.06, h=0.20, xs=0.18, xe=0.82, Ro=0.11,
               rb=None, rc=None, cy=0.5, knob=None):
    """Zwei Fluegel, ueber die Fuge hinweg ein eigener Riegelbalken in seinem
    Kanal (weisse Fuge rundum). Der Balken verbindet beide Teile: geschlossen."""
    X0 = 512 - S / 2
    Y0 = 512 - S / 2
    X1, Y1 = X0 + S, Y0 + S
    G = g * S
    xa = X0 + seam * S - G / 2
    xb = xa + G
    hh = h * S
    yc = Y0 + cy * S
    ct, cb = yc - hh / 2 - G, yc + hh / 2 + G
    XS, XE = X0 + xs * S, X0 + xe * S
    RO = Ro * S
    RB = hh / 2 if rb is None else rb * S
    RCn = RB + G if rc is None else rc * S
    left = rounded_poly(
        [(X0, Y0), (xa, Y0), (xa, ct), (XS, ct), (XS, cb), (xa, cb), (xa, Y1), (X0, Y1)],
        [RO, 0, 0, RCn, RCn, 0, 0, RO],
    )
    right = rounded_poly(
        [(xb, Y0), (X1, Y0), (X1, Y1), (xb, Y1), (xb, cb), (XE, cb), (XE, ct), (xb, ct)],
        [0, RO, RO, 0, 0, RCn, RCn, 0],
    )
    bar = rounded_poly(
        [(XS + G, ct + G), (XE - G, ct + G), (XE - G, cb - G), (XS + G, cb - G)],
        [RB, RB, RB, RB],
    )
    if knob:
        # Knauf des Schubriegels: Stummel nach unten, in einer Raste im linken Fluegel
        kx, kw, kl = knob  # Mitte x (rel.), Breite (rel.), Laenge unter dem Balken (rel.)
        KX, KW, KL = X0 + kx * S, kw * S, kl * S
        y0b = cb - G
        rk = KW / 2
        # Kanal (Raste) im linken Fluegel
        left = rounded_poly(
            [(X0, Y0), (xa, Y0), (xa, ct), (XS, ct), (XS, cb), (KX - KW / 2 - G, cb),
             (KX - KW / 2 - G, y0b + KL + G), (KX + KW / 2 + G, y0b + KL + G), (KX + KW / 2 + G, cb),
             (xa, cb), (xa, Y1), (X0, Y1)],
            [RO, 0, 0, RCn, 0, 0, rk + G, rk + G, 0, 0, 0, RO],
        )
        bar = rounded_poly(
            [(XS + G, ct + G), (XE - G, ct + G), (XE - G, cb - G), (KX + KW / 2, cb - G),
             (KX + KW / 2, y0b + KL), (KX - KW / 2, y0b + KL), (KX - KW / 2, cb - G), (XS + G, cb - G)],
            [RB, RB, RB, 0, rk, rk, 0, RB],
        )
    return [left, right, bar]


def rahmen(S=740, w=0.19, h=0.20, d=0.10, g=0.05, Ro=-0.075, ri=0.03, rb=0.02,
           hole_h=None, cy=0.5, asym=None):
    """Schwerer quadratischer Rahmen; quer durch die Oeffnung ein Sperrbalken,
    dessen Enden in Taschen in den Seitenwaenden ruhen (Sperrbalken im Tor)."""
    X0 = 512 - S / 2
    Y0 = 512 - S / 2
    X1, Y1 = X0 + S, Y0 + S
    W, H, D, G = w * S, h * S, d * S, g * S
    RI, RB = ri * S, rb * S
    yc = Y0 + cy * S
    hx0, hx1 = X0 + W, X1 - W
    hy0, hy1 = Y0 + W, Y1 - W
    if hole_h is not None:
        hh = hole_h * S
        hy0, hy1 = yc - hh / 2, yc + hh / 2
    dl, dr = (D, D) if asym is None else (asym[0] * S, asym[1] * S)
    pt, pb = yc - H / 2 - G, yc + H / 2 + G
    outer = rounded_poly([(X0, Y0), (X1, Y0), (X1, Y1), (X0, Y1)], [Ro * S] * 4)
    # Oeffnung mit Taschen links und rechts (eine zusammenhaengende Aussparung)
    hole = rounded_poly(
        [(hx0, hy0), (hx1, hy0), (hx1, pt), (hx1 + dr + G, pt), (hx1 + dr + G, pb), (hx1, pb),
         (hx1, hy1), (hx0, hy1), (hx0, pb), (hx0 - dl - G, pb), (hx0 - dl - G, pt), (hx0, pt)],
        [RI, RI, 0, RB + G, RB + G, 0, RI, RI, 0, RB + G, RB + G, 0],
    )
    bar = rounded_poly(
        [(hx0 - dl, yc - H / 2), (hx1 + dr, yc - H / 2), (hx1 + dr, yc + H / 2), (hx0 - dl, yc + H / 2)],
        [RB] * 4,
    )
    return [outer + hole, bar]


def schieber(S=740, t=0.17, x0=0.22, x1=0.78, notch=0.16, k=None, Ro=-0.075, cy=0.44):
    """Schubriegel von vorn: Fuehrungsschlitz mit Raste, Knauf in der Raste (geschlossen)."""
    X0 = 512 - S / 2
    Y0 = 512 - S / 2
    X1, Y1 = X0 + S, Y0 + S
    T = t * S
    r = T / 2
    yc = Y0 + cy * S
    xa, xb = X0 + x0 * S, X0 + x1 * S
    ny = yc + notch * S
    outer = rounded_poly([(X0, Y0), (X1, Y0), (X1, Y1), (X0, Y1)], [Ro * S] * 4)
    slot = rounded_poly(
        [(xa - r, yc - r), (xb + r, yc - r), (xb + r, ny + r), (xb - r, ny + r), (xb - r, yc + r), (xa - r, yc + r)],
        [r, r, r, r, r * 0.6, r],
    )
    K = (k or 0.62) * r
    kx, ky = xb, ny
    knob = (f"M{f(kx - K)} {f(ky)}a{f(K)} {f(K)} 0 1 0 {f(2 * K)} 0a{f(K)} {f(K)} 0 1 0 {f(-2 * K)} 0Z")
    return [outer + slot, knob]


def fuge(S=740, xc=0.5, g=0.06, teeth=((0.5, 0.30, 1, 0.30),), Ro=-0.075, ri=0.0,
         rtip=0.0, sharp=True):
    """Allgemeine Verzahnung: eine Fuge konstanter Breite G laeuft von oben nach
    unten; jeder Zahn (y-Mitte, Hoehe, Richtung +1 = links greift nach rechts,
    Laenge) ist ein Riegel, der in den anderen Teil greift. Alles relativ zu S."""
    X0 = 512 - S / 2
    Y0 = 512 - S / 2
    X1, Y1 = X0 + S, Y0 + S
    G = g * S
    XC = X0 + xc * S
    cl = [(XC, Y0)]
    for yc_, hh_, dr, L_ in teeth:
        yc, hh, L = Y0 + yc_ * S, hh_ * S, L_ * S
        ys, ye = yc - hh / 2 - G / 2, yc + hh / 2 + G / 2
        cl += [(XC, ys), (XC + dr * L, ys), (XC + dr * L, ye), (XC, ye)]
    cl.append((XC, Y1))
    h = G / 2

    def offset(sign):
        out, rad = [], []
        for i, v in enumerate(cl):
            if i == 0 or i == len(cl) - 1:
                d = (0, 1)
                n = (-d[1], d[0])
                out.append((v[0] + sign * h * n[0], v[1]))
                rad.append(0)
                continue
            a, b = cl[i - 1], cl[i + 1]
            d1 = ((v[0] - a[0]), (v[1] - a[1]))
            d2 = ((b[0] - v[0]), (b[1] - v[1]))
            l1 = (d1[0] ** 2 + d1[1] ** 2) ** 0.5
            l2 = (d2[0] ** 2 + d2[1] ** 2) ** 0.5
            d1 = (d1[0] / l1, d1[1] / l1)
            d2 = (d2[0] / l2, d2[1] / l2)
            n1 = (-d1[1], d1[0])
            n2 = (-d2[1], d2[0])
            out.append((v[0] + sign * h * (n1[0] + n2[0]), v[1] + sign * h * (n1[1] + n2[1])))
            cross = d1[0] * d2[1] - d1[1] * d2[0]
            inner = (cross > 0) == (sign > 0)   # Rechtskurve: innen = rechte Seite = linkes Teil
            is_tip = abs(v[0] - XC) > 1e-6
            r0 = rtip * S if is_tip else ri * S
            if sharp and not is_tip:
                rad.append(0)
            else:
                rad.append(r0 if inner else r0 + G)
        return out, rad

    lp, lr = offset(+1)
    rp, rr = offset(-1)
    left = rounded_poly([(X0, Y0)] + lp + [(X0, Y1)], [Ro * S] + lr + [Ro * S])
    right = rounded_poly([(X1, Y1)] + rp[::-1] + [(X1, Y0)], [Ro * S] + rr[::-1] + [Ro * S])
    return [left, right]


def raster(n=16, d=9, by0=6, bh=4, L=4, ro=1.25, M=48, X0=128, Y0=128, rtip=0.0):
    """Riegel auf einem n x n-Modulraster (Modul M). Fuge = 1 Modul.
    d = Breite Tuerblatt, by0/bh = Riegel oben/Hoehe, L = Riegellaenge ab Blattkante."""
    def P(x, y):
        return (X0 + x * M, Y0 + y * M)
    by1 = by0 + bh
    R = -ro * M   # negativ = kontinuierliche Ecke
    rt = rtip * M
    left = rounded_poly(
        [P(0, 0), P(d, 0), P(d, by0), P(d + L, by0), P(d + L, by1), P(d, by1), P(d, n), P(0, n)],
        [R, 0, 0, rt, rt, 0, 0, R],
    )
    right = rounded_poly(
        [P(d + 1, 0), P(n, 0), P(n, n), P(d + 1, n), P(d + 1, by1 + 1), P(d + L + 1, by1 + 1),
         P(d + L + 1, by0 - 1), P(d + 1, by0 - 1)],
        [0, R, R, 0, 0, rt + M if rt else 0, rt + M if rt else 0, 0],
    )
    return [left, right]


# ---------------------------------------------------------------------------
# Endstand. Das Zeichen liegt auf einem 16 x 16-Modulraster, die Fuge ist genau
# 1 Modul breit, der Riegel 4 hoch und 6 lang, der Rahmen dahinter 2 Module stark.
# ---------------------------------------------------------------------------
FINAL = dict(n=16, d=7, by0=6, bh=4, L=6, ro=1.5)


def final_mark():
    """mark.svg: Modul 48, Zeichen 768 x 768 (75 % der Flaeche), Ursprung 128."""
    return raster(M=48, X0=128, Y0=128, **FINAL)


def final_icon_mark():
    """Im Icon direkt im 1024er-Raster: Modul 32 -> Zeichen 512 (62 % des Koerpers),
    Ursprung 256. Bei 32 px ist 1 Modul = 1 Pixel: jede Kante sitzt auf dem Pixelraster."""
    return raster(M=32, X0=256, Y0=256, **FINAL)


def klein_mark():
    """icon-klein.svg fuer 16 px: dasselbe Zeichen auf 8er-Raster, Modul 64 = 1 px."""
    return raster(n=8, d=3, by0=3, bh=2, L=3, ro=0.75, M=64, X0=256, Y0=256)


VARIANTEN = {
    "final": final_mark,
    "p8r": lambda: raster(d=8, by0=6, bh=4, L=5, rtip=0.5),
    "p9r": lambda: raster(d=7, by0=6, bh=4, L=6, ro=1.5, rtip=0.5),
    "p8": lambda: raster(d=8, by0=6, bh=4, L=5),
    "p9": lambda: raster(d=7, by0=6, bh=4, L=6, ro=1.5),
    "p5": lambda: raster(d=8, by0=6, bh=4, L=6),
    "p6": lambda: raster(d=9, by0=6, bh=4, L=5),
    "p7": lambda: raster(n=14, d=8, by0=5, bh=4, L=4, M=54, X0=134, Y0=134),
    "p1": lambda: raster(d=10, by0=6, bh=4, L=4),
    "p2": lambda: raster(d=9, by0=6, bh=4, L=4),
    "p3": lambda: raster(d=9, by0=5, bh=6, L=4),
    "p4": lambda: raster(d=8, by0=6, bh=4, L=5),
    "z0": lambda: fuge(xc=0.56, teeth=((0.5, 0.34, 1, 0.26),)),
    "z1": lambda: fuge(xc=0.5, g=0.06, teeth=((0.31, 0.20, 1, 0.24), (0.69, 0.20, -1, 0.24))),
    "z2": lambda: fuge(xc=0.5, g=0.055, teeth=((0.25, 0.14, 1, 0.22), (0.5, 0.14, -1, 0.22), (0.75, 0.14, 1, 0.22))),
    "z3": lambda: fuge(xc=0.5, g=0.06, teeth=((0.34, 0.24, 1, 0.26), (0.66, 0.24, -1, 0.26))),
    "n1": lambda: querriegel(seam=0.66, g=0.055, h=0.26, xs=0.22, xe=0.87, Ro=-0.075, rb=0.025, rc=0.025 + 0.055),
    "n2": lambda: querriegel(seam=0.62, g=0.06, h=0.30, xs=0.26, xe=0.86, Ro=-0.075, rb=0.03, rc=0.03 + 0.06),
    "n3": lambda: querriegel(seam=0.50, g=0.06, h=0.30, xs=0.20, xe=0.80, Ro=-0.075, rb=0.03, rc=0.03 + 0.06),
    "k1": lambda: riegel(seam=0.56, g=0.055, h=0.36, depth=0.70, rt=0.02, sharp=True, Ro=-0.075),
    "k2": lambda: riegel(seam=0.64, g=0.055, h=0.28, depth=0.58, rt=0.0, sharp=True, Ro=-0.075),
    "m1": lambda: querriegel(seam=0.56, g=0.055, h=0.24, xs=0.16, xe=0.86, Ro=-0.075, rb=0.025, rc=0.025 + 0.055),
    "m2": lambda: querriegel(seam=0.56, g=0.055, h=0.28, xs=0.24, xe=0.84, Ro=-0.075, rb=0.025, rc=0.025 + 0.055),
    "g1": lambda: rahmen(),
    "g2": lambda: rahmen(w=0.22, h=0.22, d=0.11, g=0.05, ri=0.02),
    "g3": lambda: rahmen(w=0.18, h=0.16, d=0.09, g=0.045, ri=0.04, rb=0.08),
    "h1": lambda: schieber(),
    "f1": lambda: querriegel(seam=0.58, g=0.06, h=0.26, xs=0.18, xe=0.84, Ro=-0.075, rb=0.035, rc=0.035 + 0.06),
    "f2": lambda: querriegel(seam=0.5, g=0.06, h=0.26, xs=0.16, xe=0.84, Ro=-0.075),
    "f3": lambda: riegel(seam=0.5, g=0.06, h=0.24, depth=0.62, rt=0.03, sharp=True, Ro=-0.075),
    "f4": lambda: riegel(seam=0.40, g=0.06, h=0.30, depth=0.72, rt=0.035, sharp=False, ri=0.0, Ro=-0.075),
    "e3": lambda: querriegel(g=0.055, h=0.24, xs=0.20, xe=0.80, Ro=0.10),
    "e4": lambda: querriegel(seam=0.60, g=0.055, h=0.24, xs=0.14, xe=0.86, Ro=0.10),
    "e7": lambda: querriegel(seam=0.60, g=0.055, h=0.20, xs=0.12, xe=0.86, Ro=0.10, cy=0.44, knob=(0.34, 0.12, 0.16)),
    "a2": lambda: riegel(seam=0.60, g=0.06, h=0.30, depth=0.64, rt=0.0, sharp=True, Ro=0.09),
    "a3": lambda: riegel(seam=0.62, g=0.055, h=0.34, depth=0.66, rt=0.025, sharp=True, Ro=0.06),
    "e1": lambda: querriegel(),
    "e2": lambda: querriegel(seam=0.5, g=0.055, h=0.22, xs=0.14, xe=0.86, rb=0.02, rc=0.02 + 0.055),
    "c2": lambda: s_haken(g=0.07, a=0.28, b=0.34, Ro=0.10, ri=0.0),
    "a": lambda: riegel(),
    "b": lambda: riegel(tip_round=True),
    "c": lambda: s_haken(),
    "d": lambda: riegel(seam=0.5, h=0.32, depth=0.7, g=0.08, ri=0.03, rt=0.04),
}


def mark_svg(paths):
    body = "".join(f'<path fill-rule="evenodd" d="{p}"/>' for p in paths)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">'
        f'<g fill="#000000">{body}</g></svg>\n'
    )


def icon_svg(paths, scale=1.0):
    """macOS-Icon: weisser Squircle 824 x 824 bei (100, 100), Eckradius 185.4
    (kontinuierliche Kurve), darunter ein weicher Schatten aus halbtransparenten
    Squircles, darauf das Zeichen in Schwarz."""
    body_rect = (100, 100, 824, 824)
    r = 185.4
    shadow = []
    # weicher Schatten: gestapelte, halbtransparente Squircles (keine Filter)
    for i, (grow, dy, op) in enumerate([(-2, 4, 0.10), (0, 8, 0.06), (3, 13, 0.04), (7, 19, 0.025), (12, 26, 0.015)]):
        x, y, w, h = body_rect
        shadow.append(
            f'<path d="{squircle(x - grow, y - grow + dy, w + 2 * grow, h + 2 * grow, r + grow)}" '
            f'fill="#000000" fill-opacity="{op}"/>'
        )
    body = f'<path d="{squircle(*body_rect, r)}" fill="#FFFFFF"/>'
    t = "" if scale == 1 else f' transform="translate(512 512) scale({scale}) translate(-512 -512)"'
    mark = "".join(f'<path fill-rule="evenodd" d="{p}"/>' for p in paths)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">'
        + "".join(shadow) + body
        + f'<g fill="#000000"{t}>{mark}</g></svg>\n'
    )


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "final"
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else HIER
    out.mkdir(parents=True, exist_ok=True)
    if name == "final":
        (out / "mark.svg").write_text(mark_svg(final_mark()))
        (out / "icon.svg").write_text(icon_svg(final_icon_mark()))
        (out / "icon-klein.svg").write_text(icon_svg(klein_mark()))
    else:
        # Entwurfsrunden: Zeichen im 1024er-Raster, im Icon skaliert
        paths = VARIANTEN[name]()
        scale = float(sys.argv[3]) if len(sys.argv) > 3 else 0.62
        (out / "mark.svg").write_text(mark_svg(paths))
        (out / "icon.svg").write_text(icon_svg(paths, scale))
    print(out)
