#!/usr/bin/env python3
"""Siegel – Logo-Entwurf 05 «Kristall».

Erzeugt mark.svg und icon.svg exakt aus Geometrie (keine Handarbeit in den SVGs).
Aufruf:  python3 bau.py [variante] [ausgabeordner]
"""
import math
import os
import sys

S3 = math.sqrt(3.0)


# ---------------------------------------------------------------- Vektoren
def add(a, b): return (a[0] + b[0], a[1] + b[1])
def sub(a, b): return (a[0] - b[0], a[1] - b[1])
def mul(a, s): return (a[0] * s, a[1] * s)
def dot(a, b): return a[0] * b[0] + a[1] * b[1]
def cross(a, b): return a[0] * b[1] - a[1] * b[0]
def norm(a): return math.hypot(a[0], a[1])
def unit(a):
    n = norm(a)
    return (a[0] / n, a[1] / n)


def f(v):
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def pt(p): return f"{f(p[0])} {f(p[1])}"


def line_line(p, d, q, e):
    """Schnittpunkt der Geraden p + t d und q + s e."""
    den = cross(d, e)
    t = cross(sub(q, p), e) / den
    return add(p, mul(d, t))


def line_circle(p, d, c, r, pick="near_p"):
    """Schnittpunkte Gerade p + t d mit Kreis (c, r); liefert den gewünschten."""
    d = unit(d)
    m = sub(p, c)
    b = dot(m, d)
    cc = dot(m, m) - r * r
    disc = b * b - cc
    if disc < 0:
        raise ValueError("Gerade verfehlt Kreis")
    t1 = -b - math.sqrt(disc)
    t2 = -b + math.sqrt(disc)
    ts = sorted([t1, t2])
    t = ts[0] if pick == "first" else ts[1] if pick == "second" else min(ts, key=abs)
    return add(p, mul(d, t))


# ---------------------------------------------------------------- Pfadbau
class Shape:
    """Geschlossene Kontur aus Knoten. Knoten: (punkt, eckradius) oder ('arc', mitte, radius)
    als Kante zum nächsten Knoten (konkaver/konvexer Kreisbogen um 'mitte')."""

    def __init__(self):
        self.items = []

    def p(self, point, r=0.0):
        self.items.append(("P", point, r))
        return self

    def arc(self, centre, radius, large=False):
        self.items.append(("A", centre, radius, large))
        return self

    def path(self):
        # Punkte mit Info, ob die Kante danach ein Bogen ist
        nodes = []
        for it in self.items:
            if it[0] == "P":
                nodes.append({"p": it[1], "r": it[2], "arc": None})
            else:
                nodes[-1]["arc"] = (it[1], it[2], it[3] if len(it) > 3 else False)
        n = len(nodes)
        # Für jeden Knoten: Eintritts- und Austrittspunkt (bei Rundung)
        enter, leave, fillet = [], [], []
        for i, nd in enumerate(nodes):
            prev = nodes[i - 1]
            nxt = nodes[(i + 1) % n]
            v = nd["p"]
            r = nd["r"]
            if r > 0 and prev["arc"] is None and nd["arc"] is None:
                a = unit(sub(prev["p"], v))
                b = unit(sub(nxt["p"], v))
                ang = math.acos(max(-1, min(1, dot(a, b))))
                t = r / math.tan(ang / 2)
                t1 = add(v, mul(a, t))
                t2 = add(v, mul(b, t))
                d1 = mul(a, -1)
                d2 = b
                sweep = 1 if cross(d1, d2) > 0 else 0
                enter.append(t1)
                leave.append(t2)
                fillet.append((r, sweep))
            else:
                enter.append(v)
                leave.append(v)
                fillet.append(None)
        out = [f"M{pt(leave[0])}"]
        for k in range(1, n + 1):
            i = k % n
            prev = nodes[k - 1]
            if prev["arc"] is not None:
                c, rad, large = prev["arc"]
                a1 = math.atan2(leave[k - 1][1] - c[1], leave[k - 1][0] - c[0])
                a2 = math.atan2(enter[i][1] - c[1], enter[i][0] - c[0])
                d = (a2 - a1 + math.pi) % (2 * math.pi) - math.pi
                sweep = 1 if d > 0 else 0
                if large:
                    sweep = 1 - sweep
                out.append(f"A{f(rad)} {f(rad)} 0 {1 if large else 0} {sweep} {pt(enter[i])}")
            else:
                out.append(f"L{pt(enter[i])}")
            if fillet[i] is not None:
                r, sw = fillet[i]
                out.append(f"A{f(r)} {f(r)} 0 0 {sw} {pt(leave[i])}")
        out.append("Z")
        return "".join(out)


# ---------------------------------------------------------------- Squircle (kontinuierliche Ecke)
# Koeffizienten der iOS-/macOS-Ecke (kontinuierliche Krümmung), symmetrisch zur Diagonalen.
K = [
    ((1.08849323, 0.0), (0.86840689, 0.0), (0.66993427, 0.06549600)),
    ((0.37282392, 0.16362043), (0.16362043, 0.37282392), (0.06549600, 0.66993427)),
    ((0.0, 0.86840689), (0.0, 1.08849323), (0.0, 1.52866483)),
]
K0 = 1.52866483


def squircle(x, y, w, h, r):
    corners = [
        ((x, y), (0, -1), (1, 0)),
        ((x + w, y), (1, 0), (0, 1)),
        ((x + w, y + h), (0, 1), (-1, 0)),
        ((x, y + h), (-1, 0), (0, -1)),
    ]

    def m(cp, din, dout, X, Y):
        return (cp[0] - X * r * din[0] + Y * r * dout[0], cp[1] - X * r * din[1] + Y * r * dout[1])

    out = []
    for j, (cp, din, dout) in enumerate(corners):
        start = m(cp, din, dout, K0, 0)
        out.append(("M" if j == 0 else "L") + pt(start))
        for c1, c2, e in K:
            out.append("C" + " ".join(pt(m(cp, din, dout, *q)) for q in (c1, c2, e)))
    out.append("Z")
    return "".join(out)


# ---------------------------------------------------------------- Das Zeichen
DEFAULT = dict(
    cx=512.0, cy=512.0, R=400.0,   # Hexagon (Spitze oben), Umkreisradius
    g=34.0,                        # Fugenbreite der beiden oberen Würfelkanten
    rk=78.0,                       # Radius Schlüsselloch-Kopf (sitzt in der vorderen Würfelecke)
    hw1=26.0, hw2=52.0,            # halbe Schaftbreite oben / unten (Schaft = vordere senkrechte Kante)
    slot_end=None,                 # None = Schaft bis zur Unterkante; sonst y-Ende des Trapezes
    rc=44.0,                       # Rundung der Hexagon-Aussenecken (120°)
    rt=14.0,                       # Rundung der spitzen 60°-Ecken an den Fugenmündungen
    rb=10.0,                       # Rundung der Ecken am Schaftende
    rj=0.0,                        # (reserviert)
)


def mark_paths(o):
    cx, cy, R = o["cx"], o["cy"], o["R"]
    C = (cx, cy)
    h = R * S3 / 2
    T = (cx, cy - R)
    UR = (cx + h, cy - R / 2)
    LR = (cx + h, cy + R / 2)
    B = (cx, cy + R)
    LL = (cx - h, cy + R / 2)
    UL = (cx - h, cy - R / 2)
    g2 = o["g"] / 2
    rk = o["rk"]

    u_ul = unit(sub(UL, C))
    u_ur = unit(sub(UR, C))
    # Normalen der Fugen
    n_ur_top = (-0.5, -S3 / 2)   # von Kante C-UR in Richtung Deckfläche
    n_ul_top = (0.5, -S3 / 2)
    n_ur_right = (0.5, S3 / 2)   # von Kante C-UR in Richtung rechte Fläche
    n_ul_left = (-0.5, S3 / 2)

    # --- Deckfläche
    p_ur_t = add(C, mul(n_ur_top, g2))
    p_ul_t = add(C, mul(n_ul_top, g2))
    X1 = line_line(p_ur_t, u_ur, T, sub(UR, T))
    X0 = line_line(p_ul_t, u_ul, T, sub(UL, T))
    Q1 = line_circle(p_ur_t, u_ur, C, rk, pick="second")
    Q2 = line_circle(p_ul_t, u_ul, C, rk, pick="second")
    top = Shape().p(X0, o["rt"]).p(T, o["rc"]).p(X1, o["rt"]).p(Q1).arc(C, rk).p(Q2)

    # --- Schaft (vordere senkrechte Kante als Schlüssellochschaft)
    def slot_x(y, side):
        t = (y - cy) / (B[1] - cy)
        hw = o["hw1"] + (o["hw2"] - o["hw1"]) * t
        return cx + side * hw

    faces = [top]
    if o.get("closed"):
        # Linke + rechte Fläche als ein Körper; Schlüsselloch endet geschlossen über der Unterecke.
        ye = o["closed"]
        sh = Shape()
        side_pts = {}
        for side in (-1, 1):
            n_up = n_ul_left if side < 0 else n_ur_right
            u_up = u_ul if side < 0 else u_ur
            OUT_UP = UL if side < 0 else UR
            OUT_LO = LL if side < 0 else LR
            p_up = add(C, mul(n_up, g2))
            Xa = line_line(p_up, u_up, OUT_UP, sub(OUT_LO, OUT_UP))
            Qa = line_circle(p_up, u_up, C, rk, pick="second")
            s0 = (slot_x(cy, side), cy)
            s1 = (slot_x(ye, side), ye)
            Qb = line_circle(s0, sub(s1, s0), C, rk, pick="second")
            side_pts[side] = (Xa, Qa, Qb, s1, OUT_LO)
        Xa, Qa, Qb, s1, LO = side_pts[-1]
        sh.p(Xa, o["rt"]).p(Qa).arc(C, rk).p(Qb).p(s1, o["rb"])
        Xa2, Qa2, Qb2, s12, LO2 = side_pts[1]
        sh.p(s12, o["rb"]).p(Qb2).arc(C, rk).p(Qa2).p(Xa2, o["rt"]).p(LO2, o["rc"]).p(B, o["rc"]).p(LO, o["rc"])
        faces.append(sh)
        return [s.path() for s in faces]
    for side in (-1, 1):
        # side -1: linke Fläche, +1: rechte Fläche (gespiegelt)
        n_up = n_ul_left if side < 0 else n_ur_right
        u_up = u_ul if side < 0 else u_ur
        OUT_UP = UL if side < 0 else UR
        OUT_LO = LL if side < 0 else LR
        p_up = add(C, mul(n_up, g2))
        Xa = line_line(p_up, u_up, OUT_UP, sub(OUT_LO, OUT_UP))
        Qa = line_circle(p_up, u_up, C, rk, pick="second")
        # Schaftlinie
        if o["slot_end"] is None:
            s0 = (slot_x(cy, side), cy)
            s1 = (slot_x(B[1], side), B[1])
            dsl = sub(s1, s0)
            Qb = line_circle(s0, dsl, C, rk, pick="second")
            Xb = line_line(s0, dsl, B, sub(OUT_LO, B))
            pts = [(Qb, 0), (Xb, o["rb"])]
        else:
            ye = o["slot_end"]
            s0 = (slot_x(cy, side), cy)
            s1 = (slot_x(ye, side), ye)
            dsl = sub(s1, s0)
            Qb = line_circle(s0, dsl, C, rk, pick="second")
            # Stufe nach innen auf die schmale Fuge, dann zur Unterkante
            xin = cx + side * g2
            st1 = s1
            st2 = (xin, ye)
            Xb = line_line(st2, (0, 1), B, sub(OUT_LO, B))
            pts = [(Qb, 0), (st1, o["rb"]), (st2, 0), (Xb, o["rt"])]
        sh = Shape()
        if side < 0:
            # Uhrzeigersinn: Xa -> Qa (Bogen) -> Qb -> ... -> Xb -> LL -> Xa
            sh.p(Xa, o["rt"]).p(Qa).arc(C, rk)
            for q, r in pts:
                sh.p(q, r)
            sh.p(OUT_LO, o["rc"])
        else:
            sh.p(Xa, o["rt"]).p(OUT_LO, o["rc"])
            for q, r in reversed(pts):
                sh.p(q, r)
            # letzter Punkt ist Qb, Bogen zurück zu Qa
            sh.items.append(("A", C, rk))
            sh.p(Qa)
        faces.append(sh)
    return [s.path() for s in faces]


def mark_paths_hex(o):
    """Schlüsselloch mit sechseckigem Kopf: der Kristall im Kristall.
    Alle Kanten liegen auf dem Isometrie-Raster (90°, 30°, 150°) – ausser dem leicht konischen Schaft."""
    cx, cy, R = o["cx"], o["cy"], o["R"]
    C = (cx, cy)
    h = R * S3 / 2
    T, UR, LR = (cx, cy - R), (cx + h, cy - R / 2), (cx + h, cy + R / 2)
    B, LL, UL = (cx, cy + R), (cx - h, cy + R / 2), (cx - h, cy - R / 2)
    g2 = o["g"] / 2
    rh = o["rh"]
    hh = rh * S3 / 2
    hc = (cx, cy + o.get("hdy", 0.0))           # Kopfmitte (darf leicht unter der Würfelecke sitzen)
    t = (hc[0], hc[1] - rh)
    ur, lr = (hc[0] + hh, hc[1] - rh / 2), (hc[0] + hh, hc[1] + rh / 2)
    b = (hc[0], hc[1] + rh)
    ll, ul = (hc[0] - hh, hc[1] + rh / 2), (hc[0] - hh, hc[1] - rh / 2)
    u_ul, u_ur = unit(sub(UL, C)), unit(sub(UR, C))
    n_ur_top, n_ul_top = (-0.5, -S3 / 2), (0.5, -S3 / 2)
    n_ur_right, n_ul_left = (0.5, S3 / 2), (-0.5, S3 / 2)
    rc, rt, rb, ri = o["rc"], o["rt"], o["rb"], o.get("ri", 0.0)

    # Deckfläche
    p_r = add(C, mul(n_ur_top, g2))
    p_l = add(C, mul(n_ul_top, g2))
    X1 = line_line(p_r, u_ur, T, sub(UR, T))
    X0 = line_line(p_l, u_ul, T, sub(UL, T))
    Qr = line_line(p_r, u_ur, t, sub(ur, t))
    Ql = line_line(p_l, u_ul, t, sub(ul, t))
    top = Shape().p(X0, rt).p(T, rc).p(X1, rt).p(Qr, ri).p(t, ri).p(Ql, ri)

    # Seitenflächen als ein Körper, Schaft geschlossen
    ye = o["closed"]

    def hw(y):
        return o["hw1"] + (o["hw2"] - o["hw1"]) * (y - cy) / (B[1] - cy)

    pl = add(C, mul(n_ul_left, g2))
    pr = add(C, mul(n_ur_right, g2))
    Xa = line_line(pl, u_ul, UL, sub(LL, UL))
    Xa2 = line_line(pr, u_ur, UR, sub(LR, UR))
    Qa = line_line(pl, u_ul, ul, (0, 1))
    Qa2 = line_line(pr, u_ur, ur, (0, 1))
    sl0, sl1 = (cx - hw(cy), cy), (cx - hw(ye), ye)
    sr0, sr1 = (cx + hw(cy), cy), (cx + hw(ye), ye)
    Sl = line_line(sl0, sub(sl1, sl0), ll, sub(b, ll))
    Sr = line_line(sr0, sub(sr1, sr0), lr, sub(b, lr))
    body = Shape().p(Xa, rt).p(Qa, ri).p(ll, ri).p(Sl, ri).p(sl1, rb).p(sr1, rb).p(Sr, ri).p(lr, ri) \
        .p(Qa2, ri).p(Xa2, rt).p(LR, rc).p(B, rc).p(LL, rc)
    return [top.path(), body.path()]


def mark_paths_solid(o):
    """Kleinstgrössen (16 px): Würfelfugen entfallen, nur Hexagon mit Schlüsselloch (evenodd)."""
    cx, cy, R = o["cx"], o["cy"], o["R"]
    C = (cx, cy)
    h = R * S3 / 2
    hexa = Shape()
    for q in [(cx, cy - R), (cx + h, cy - R / 2), (cx + h, cy + R / 2), (cx, cy + R), (cx - h, cy + R / 2), (cx - h, cy - R / 2)]:
        hexa.p(q, o["rc"])
    rk, ye = o["rk"], o["closed"]
    By = cy + R
    C = (cx, cy + o.get("hdy", 0.0))   # Kopf darf für das Pixelraster leicht verschoben sein

    def hw(y):
        return o["hw1"] + (o["hw2"] - o["hw1"]) * (y - cy) / (By - cy)

    sl0, sl1 = (cx - hw(cy), cy), (cx - hw(ye), ye)
    sr0, sr1 = (cx + hw(cy), cy), (cx + hw(ye), ye)
    Ql = line_circle(sl0, sub(sl1, sl0), C, rk, pick="second")
    Qr = line_circle(sr0, sub(sr1, sr0), C, rk, pick="second")
    hole = Shape().p(Ql).p(sl1, o["rb"]).p(sr1, o["rb"]).p(Qr).arc(C, rk, large=True)
    return [hexa.path(), hole.path()]


def paths(o):
    if o.get("solid"):
        return mark_paths_solid(o)
    return mark_paths_hex(o) if o.get("rh") else mark_paths(o)


HEAD = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">'


def mark_svg(o, fill="#000"):
    d = " ".join(paths(o))
    return f'{HEAD}\n  <path fill="{fill}" fill-rule="evenodd" d="{d}"/>\n</svg>\n'


def icon_svg(o, scale=0.6, dy=0.0, shadow=True):
    body = squircle(100, 100, 824, 824, 185.4)
    parts = [HEAD]
    if shadow:
        # sehr dezente Schattenkante: gestapelte, leicht vergrösserte und nach unten versetzte
        # Körperformen mit kleiner Deckkraft (keine Filter)
        layers = 9
        for i in range(layers, 0, -1):
            grow = i * 1.1
            off = 3 + i * 1.7
            parts.append(
                f'  <path fill="#000" fill-opacity="0.011" d="{squircle(100 - grow, 100 - grow + off, 824 + 2 * grow, 824 + 2 * grow, 185.4 + grow)}"/>'
            )
    parts.append(f'  <path fill="#FFF" d="{body}"/>')
    tx = 512 - 512 * scale
    ty = 512 - 512 * scale + dy
    d = " ".join(paths(o))
    parts.append(f'  <g transform="translate({f(tx)} {f(ty)}) scale({f(scale)})">')
    parts.append(f'    <path fill="#000" fill-rule="evenodd" d="{d}"/>')
    parts.append("  </g>")
    parts.append("</svg>\n")
    return "\n".join(parts)


# Endgültige Geometrie (Runde 4). Masse in Einheiten der 1024er-viewBox des Zeichens.
FINAL = dict(
    cx=512.0, cy=512.0, R=400.0,
    g=36.0,                 # Würfelfugen
    rk=80.0,                # Schlüsselloch-Kopf, sitzt exakt in der vorderen Würfelecke
    hw1=26.0, hw2=62.0,     # konischer Schaft = vordere senkrechte Würfelkante
    closed=764.0,           # Schaftende; darunter bleibt der Würfel versiegelt
    rc=32.0, rt=16.0, rb=14.0,
)
# Optische Korrektur für 32 px: kräftigere Fugen, grösserer Kopf, grösseres Zeichen
KLEIN = dict(FINAL, g=58.0, rk=104.0, hw1=36.0, hw2=74.0, closed=776.0, rc=40.0, rt=22.0, rb=20.0)
# 16 px: Fugen entfallen (unter 1 px), Hexagon + Schlüsselloch, auf das 16er-Pixelraster gelegt.
MINI_SCALE = 0.72


def _px(py, s=MINI_SCALE):
    """Pixelzeile im 16-px-Icon -> y in Zeichen-Einheiten."""
    return (py * 64 - (512 - 512 * s)) / s


_U = 64 / MINI_SCALE  # Zeichen-Einheiten pro Pixel bei 16 px
MINI = dict(FINAL, solid=True,
            rk=1.7 * _U,                 # Kopf ~3.4 px
            hw1=1.0 * _U, hw2=1.0 * _U,  # Schaft genau 2 px breit, auf Pixelgrenzen 7..9
            hdy=_px(7.6) - 512.0,        # Kopf leicht angehoben, damit der Schaft Platz hat
            closed=_px(11.2),
            rc=40.0, rb=16.0)

VARIANTEN = {
    "a": dict(),
    "a2": dict(slot_end=700.0, hw1=24.0, hw2=40.0),
    "r2a": dict(g=34, rk=80, hw1=24, hw2=48, rc=38, rt=18, rb=16),
    "r2b": dict(g=46, rk=94, hw1=30, hw2=58, rc=38, rt=20, rb=18),
    "r2c": dict(g=34, rk=80, hw1=28, hw2=28, rc=38, rt=18, rb=16),
    "r2d": dict(g=34, rk=80, hw1=26, hw2=62, rc=38, rt=18, rb=16, closed=772),
    "r3a": dict(g=34, rk=80, hw1=26, hw2=62, rc=30, rt=16, rb=14, closed=764),
    "r3h": dict(g=34, rh=92, hw1=26, hw2=62, rc=30, rt=16, rb=14, ri=4, closed=764),
    "r3h2": dict(g=36, rh=100, hdy=0, hw1=30, hw2=30, rc=30, rt=16, rb=14, ri=4, closed=772),
    "r3h3": dict(g=34, rh=88, hw1=24, hw2=58, rc=22, rt=12, rb=12, ri=3, closed=764),
}


def schreibe(pfad, text):
    with open(pfad, "w") as fh:
        fh.write(text)


if __name__ == "__main__":
    var = sys.argv[1] if len(sys.argv) > 1 else "final"
    hier = os.path.dirname(os.path.abspath(__file__))
    outdir = sys.argv[2] if len(sys.argv) > 2 else hier
    os.makedirs(outdir, exist_ok=True)
    if var == "final":
        schreibe(os.path.join(outdir, "mark.svg"), mark_svg(FINAL))
        schreibe(os.path.join(outdir, "icon.svg"), icon_svg(FINAL, scale=0.6))
        schreibe(os.path.join(outdir, "icon-32.svg"), icon_svg(KLEIN, scale=0.64))
        schreibe(os.path.join(outdir, "icon-16.svg"), icon_svg(MINI, scale=MINI_SCALE))
    else:
        o = dict(DEFAULT)
        o.update(VARIANTEN.get(var, {}))
        schreibe(os.path.join(outdir, "mark.svg"), mark_svg(o))
        schreibe(os.path.join(outdir, "icon.svg"), icon_svg(o))
    print("ok", var, outdir)
