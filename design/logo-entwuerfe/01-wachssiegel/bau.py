#!/usr/bin/env python3
"""Siegel-Logo, Entwurf 01 "Wachssiegel" - reproduzierbarer Bau aller SVGs (und PNGs).

    python3 bau.py                 # schreibt mark.svg, icon.svg, icon-klein.svg
    python3 bau.py --render <svg_render-Binary>   # zusaetzlich alle PNGs

Geometrie (alles exakt berechnet, nur <path>, fill-rule="evenodd"):
- Rand: Wachs-Kontur r(t) = R * (1 + 0.034 cos 7t - 0.009 cos 14t), 7 Wuelste; die negative
  2. Harmonische macht die Wuelste breit und die Taeler knapper, wie ausfliessendes Wachs.
  Als kubische Bezier-Kurven mit exakten Tangenten (Hermite), 280 Segmente.
- Perlrand: 28 Perlen (4 pro Wulst, je eine auf Kamm und Tal) auf Kreis 0.78 R.
- Schluesselloch: Kopfkreis + konischer Schaft, Hohlkehlen am Uebergang, gerundete Fusskanten.
- App-Icon: macOS-Koerper 824x824 bei (100,100), kontinuierliche Ecke (r = 185.4,
  iOS/macOS-Squircle-Konstruktion), Schatten aus 8 halbtransparenten Lagen statt Filter.
"""
import math, os, subprocess, sys

HIER = os.path.dirname(os.path.abspath(__file__))

def f(v):
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s

def pt(x, y):
    return f"{f(x)} {f(y)}"

# ---------- kontinuierliche Ecke (Squircle) ----------
def squircle(x, y, w, h, r):
    seq = [
        ("C", (1.08849323, 0), (0.86840689, 0), (0.66993427, 0.06549600)),
        ("L", (0.63149399, 0.07491100)),
        ("C", (0.37282392, 0.16905899), (0.16906013, 0.37282401), (0.07491176, 0.63149399)),
        ("L", (0.06549569, 0.66993427)),
        ("C", (0, 0.86840701), (0, 1.08849299), (0, 1.52866483)),
    ]
    k = 1.52866483
    tr = lambda dx, dy: (x + w - dx * r, y + dy * r)
    br = lambda dx, dy: (x + w - dy * r, y + h - dx * r)
    bl = lambda dx, dy: (x + dx * r, y + h - dy * r)
    tl = lambda dx, dy: (x + dy * r, y + dx * r)
    out = [f"M{pt(x + k * r, y)}", f"L{pt(x + w - k * r, y)}"]
    for corner, nxt in ((tr, f"L{pt(x + w, y + h - k * r)}"), (br, f"L{pt(x + k * r, y + h)}"),
                        (bl, f"L{pt(x, y + k * r)}"), (tl, "Z")):
        for s in seq:
            if s[0] == "C":
                a, b, c = (corner(*p) for p in s[1:])
                out.append(f"C{pt(*a)} {pt(*b)} {pt(*c)}")
            else:
                out.append(f"L{pt(*corner(*s[1]))}")
        out.append(nxt)
    return " ".join(out)

def circle(cx, cy, r):
    return (f"M{pt(cx - r, cy)} A{f(r)} {f(r)} 0 1 1 {pt(cx + r, cy)} "
            f"A{f(r)} {f(r)} 0 1 1 {pt(cx - r, cy)} Z")

# ---------- Wachs-Kontur ----------
def wachsrand(cx, cy, R, harmonische, segmente):
    def P(t):
        r, dr = R, 0.0
        for a, n in harmonische:
            r += a * math.cos(n * (t + math.pi / 2))
            dr -= a * n * math.sin(n * (t + math.pi / 2))
        return (cx + r * math.cos(t), cy + r * math.sin(t),
                dr * math.cos(t) - r * math.sin(t), dr * math.sin(t) + r * math.cos(t))
    dt = 2 * math.pi / segmente
    t0 = -math.pi / 2
    x0, y0, _, _ = P(t0)
    out = [f"M{pt(x0, y0)}"]
    for i in range(segmente):
        xa, ya, dxa, dya = P(t0 + i * dt)
        xb, yb, dxb, dyb = P(t0 + (i + 1) * dt)
        out.append(f"C{pt(xa + dxa * dt / 3, ya + dya * dt / 3)} "
                   f"{pt(xb - dxb * dt / 3, yb - dyb * dt / 3)} {pt(xb, yb)}")
    return " ".join(out) + " Z"

def perlrand(cx, cy, n, Rb, rb):
    return " ".join(circle(cx + Rb * math.cos(-math.pi / 2 + i * 2 * math.pi / n),
                           cy + Rb * math.sin(-math.pi / 2 + i * 2 * math.pi / n), rb) for i in range(n))

# ---------- Schluesselloch ----------
def schluesselloch(cx, cy, rho, yh, wt, wb, yb, rc, fr):
    """Kopfkreis (cx, cy+yh), Radius rho. Schaftseite durch (+-wt, yh) und (+-wb, yb).
    rc: Rundung der Fusskanten, fr: Hohlkehle zwischen Kopf und Schaft."""
    p0 = (wt, yh)
    dx, dy = wb - wt, yb - yh
    L = math.hypot(dx, dy); u = (dx / L, dy / L)
    n = (u[1], -u[0])
    if n[0] < 0:
        n = (-n[0], -n[1])
    ox, oy = p0[0] + fr * n[0], p0[1] + fr * n[1] - yh
    B = 2 * (ox * u[0] + oy * u[1]); Cq = ox * ox + oy * oy - (rho + fr) ** 2
    s = (-B + math.sqrt(B * B - 4 * Cq)) / 2
    c = (p0[0] + s * u[0] + fr * n[0], p0[1] + s * u[1] + fr * n[1])
    k = rho / (rho + fr)
    tc = (c[0] * k, yh + (c[1] - yh) * k)           # Tangente auf dem Kopfkreis
    tl = (c[0] - fr * n[0], c[1] - fr * n[1])       # Tangente auf der Schaftseite
    winkel = math.acos(u[0])                         # Innenwinkel Seite/Fuss
    d = rc / math.tan(winkel / 2)
    seite_ende = (wb - u[0] * d, yb - u[1] * d)
    fuss_start = (wb - d, yb)
    P = lambda x, y: pt(cx + x, cy + y)
    return " ".join([
        f"M{P(-tc[0], tc[1])}",
        f"A{f(rho)} {f(rho)} 0 1 1 {P(*tc)}",
        f"A{f(fr)} {f(fr)} 0 0 0 {P(*tl)}",
        f"L{P(*seite_ende)}",
        f"A{f(rc)} {f(rc)} 0 0 1 {P(*fuss_start)}",
        f"L{P(-fuss_start[0], fuss_start[1])}",
        f"A{f(rc)} {f(rc)} 0 0 1 {P(-seite_ende[0], seite_ende[1])}",
        f"L{P(-tl[0], tl[1])}",
        f"A{f(fr)} {f(fr)} 0 0 0 {P(-tc[0], tc[1])}",
        "Z"])

# ---------- das Zeichen ----------
WACHS = [(0.034, 7), (-0.009, 14)]
SCHLUESSELLOCH = dict(rho=0.30, yh=-0.13, wt=0.105, wb=0.19, yb=0.58, rc=0.03, fr=0.03)

def zeichen(aussen, perlen=True, loch_skala=1.0, cx=512.0, cy=512.0):
    """aussen = Radius der Wulstkaemme. Die Kontur ist oben (Kamm) hoeher als unten (Tal),
    darum sitzt die Mitte um 1.2 % R tiefer: optisch zentriert zwischen Masse und Umriss."""
    R = aussen / (1 + WACHS[0][0] + WACHS[1][0])
    cy = cy + 0.012 * R
    d = wachsrand(cx, cy, R, [(a * R, n) for a, n in WACHS], 7 * 40)
    if perlen:
        d += " " + perlrand(cx, cy, 28, 0.78 * R, 0.033 * R)
    k = {key: v * R * (loch_skala if key != "fr" else 1.0) for key, v in SCHLUESSELLOCH.items()}
    d += " " + schluesselloch(cx, cy - 0.065 * R * loch_skala, **k)
    return d

def svg(inhalt, titel):
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">\n'
            f"{inhalt}\n</svg>\n")

def icon(mark_d):
    teile = []
    for i in range(8):  # weicher Schatten ohne Filter: 8 Lagen, je 2.2 % Schwarz
        e = 14 * (i + 1) / 8
        teile.append(f'<path fill="#000" fill-opacity="0.022" d="{squircle(100 - e, 100 - e + 10, 824 + 2 * e, 824 + 2 * e, 185.4 + e)}"/>')
    teile.append(f'<path fill="#fff" d="{squircle(100, 100, 824, 824, 185.4)}"/>')
    teile.append(f'<path fill="#000" fill-rule="evenodd" d="{mark_d}"/>')
    return "\n".join(teile)

def main():
    dateien = {
        "mark.svg": svg(f'<path fill="#000" fill-rule="evenodd" d="{zeichen(383)}"/>', "Siegel"),
        "icon.svg": svg(icon(zeichen(246)), "Siegel"),
        # Kleingroessen (16/32 px): ohne Perlrand, Zeichen und Schluesselloch groesser
        "icon-klein.svg": svg(icon(zeichen(300, perlen=False, loch_skala=1.18)), "Siegel"),
    }
    for name, inhalt in dateien.items():
        with open(os.path.join(HIER, name), "w") as fh:
            fh.write(inhalt)
    if "--render" in sys.argv:
        r = sys.argv[sys.argv.index("--render") + 1]
        def go(src, dst, px, bg):
            subprocess.run([r, os.path.join(HIER, src), os.path.join(HIER, dst), str(px), bg], check=True)
        go("icon.svg", "icon-1024.png", 1024, "#EDEDED")
        go("icon.svg", "icon-128.png", 128, "#EDEDED")
        go("icon.svg", "icon-32.png", 32, "#EDEDED")
        go("icon.svg", "icon-16.png", 16, "#EDEDED")
        go("icon-klein.svg", "icon-klein-32.png", 32, "#EDEDED")
        go("icon-klein.svg", "icon-klein-16.png", 16, "#EDEDED")
        go("mark.svg", "mark-512.png", 512, "white")

if __name__ == "__main__":
    main()
