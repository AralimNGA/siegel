#!/usr/bin/env python3
"""Siegel-Logo, Entwurf 02 "Gitter" – erzeugt mark.svg und icon.svg aus exakter Geometrie.

Idee: ein schwarzes Siegel (Scheibe mit Gravurring), perforiert von einem quadratischen
Punktgitter (Gitterabstand p, Lochradius r, Stegbreite w = p - 2r). Das Schluesselloch ist
kein fremdes Element, sondern aus dem Gitter geschnitten:
  - Kopf: Kreis in einer Zellmitte. Radius R = (sqrt(6.5) - 1) p + r, d. h. die 8 Gitterpunkte
    auf der Schale |v| = sqrt(6.5) p liegen exakt eine Stegbreite w vom Kopf entfernt.
  - Schaft: nimmt genau die zwei mittleren Spalten weg, Halbbreite s = 0.5 p + r, damit liegen
    die Spalten bei x = +-1.5 p exakt eine Stegbreite neben dem Schaft. Rundes Ende in einer Zellmitte.
  - Gravurring: aussen eine Stegbreite Rand, innen eine Stegbreite bis zu den Loechern.
Ueberall dieselbe Materialstaerke w: wie ein gestanztes Blech.
Kopfzentrum und Gitter liegen so, dass das Lochfeld zur Scheibenmitte symmetrisch ist.

Aufruf:  python3 bau_logo.py [ausgabeordner] [schluessel=wert ...]
         (ohne Argumente: schreibt mark.svg + icon.svg neben dieses Skript)
"""
import math
import sys
import os

P = dict(
    D=372.0,          # Radius der Siegelscheibe (mark.svg, viewBox 1024) -> Durchmesser 744 = 73 %
    p=62.0,           # Gitterabstand
    rr=0.32,          # Lochradius als Anteil von p
    cell=1,           # 0 = Kopf auf Gitterpunkt, 1 = Kopf in Zellmitte
    Rsh=math.sqrt(6.5),  # Gitterschale, die den Kopf umschliesst (in p)
    Ssh=1.5,          # Abstand der ersten Spalte neben dem Schaft (in p)
    slot=4,           # Schaftende (Kappenmitte) slot*p unter dem Kopfzentrum
    hy_off=-1.5,      # Kopfzentrum = 512 + hy_off * p
    rim=1.0,          # ohne Gravurring: Mindest-Randsteg in Stegbreiten
    ring=0.5,         # Gravurring-Breite in Stegbreiten (0 = kein Ring)
    moat=1.0,         # Abstand Loch <-> Schluesselloch in Stegbreiten
    fillet=0.5,       # Ausrundung Kopf/Schaft (Anteil von r)
    mode=0,           # 0 = gelochte Scheibe; 1 = positive Punkte (verworfen); 2 = Kleinformat ohne Gitter
    icon_scale=0.64,  # Zeichen im App-Icon relativ zu mark.svg (Scheibe = 58 % des Koerpers)
    icon_dy=0.0,
    shadow=1,
)


def fmt(v):
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def circle_path(cx, cy, r):
    return (f"M{fmt(cx - r)} {fmt(cy)}a{fmt(r)} {fmt(r)} 0 1 0 {fmt(2 * r)} 0"
            f"a{fmt(r)} {fmt(r)} 0 1 0 {fmt(-2 * r)} 0Z")


def keyhole_path(cx, hy, R, s, L, f):
    """Kopfkreis (cx,hy,R) vereinigt mit Schaft (Halbbreite s) bis Kappenmitte hy+L, Kappe Radius s.
    f = Radius der konkaven Ausrundung am Uebergang Kopf/Schaft (0 = scharf)."""
    if f <= 0:
        yj = hy + math.sqrt(R * R - s * s)
        return (f"M{fmt(cx - s)} {fmt(yj)}"
                f"A{fmt(R)} {fmt(R)} 0 1 1 {fmt(cx + s)} {fmt(yj)}"
                f"L{fmt(cx + s)} {fmt(hy + L)}"
                f"A{fmt(s)} {fmt(s)} 0 0 1 {fmt(cx - s)} {fmt(hy + L)}Z")
    # Ausrundungskreis: Mittelpunkt bei x = cx + s + f, tangential zum Kopfkreis (Abstand R + f)
    fx = s + f
    fy = math.sqrt((R + f) ** 2 - fx ** 2)
    # Tangentialpunkt am Kopfkreis
    tx, ty = fx * R / (R + f), fy * R / (R + f)
    # Tangentialpunkt am Schaft
    sx, sy = s, fy
    return (f"M{fmt(cx - sx)} {fmt(hy + sy)}"
            f"A{fmt(f)} {fmt(f)} 0 0 0 {fmt(cx - tx)} {fmt(hy + ty)}"
            f"A{fmt(R)} {fmt(R)} 0 1 1 {fmt(cx + tx)} {fmt(hy + ty)}"
            f"A{fmt(f)} {fmt(f)} 0 0 0 {fmt(cx + sx)} {fmt(hy + sy)}"
            f"L{fmt(cx + s)} {fmt(hy + L)}"
            f"A{fmt(s)} {fmt(s)} 0 0 1 {fmt(cx - s)} {fmt(hy + L)}Z")


def dist_to_keyhole(x, y, cx, hy, R, s, L):
    """Abstand eines Punkts zum Schluesselloch (negativ = innen)."""
    d_head = math.hypot(x - cx, y - hy) - R
    # Schaft als Kapsel von (cx,hy) bis (cx,hy+L), Radius s
    t = min(max(y - hy, 0.0), L)
    d_slot = math.hypot(x - cx, y - (hy + t)) - s
    return min(d_head, d_slot)


def build_mark(prm):
    """Gitter: Punkte bei Kopfzentrum + ((i + cell/2) p, (j + cell/2) p).
    Kopfradius R = (Rsh - 1) p + r  -> Gitterpunkte auf der Schale |v| = Rsh p liegen genau eine Stegbreite w entfernt.
    Schaft-Halbbreite s = (Ssh - 1) p + r -> Spalten bei x = +-Ssh p liegen genau eine Stegbreite entfernt."""
    c = 512.0
    D, p = prm["D"], prm["p"]
    r = prm["rr"] * p
    w = p - 2 * r
    R = (prm["Rsh"] - 1) * p + r
    s = (prm["Ssh"] - 1) * p + r
    L = prm["slot"] * p
    hy = c + prm["hy_off"] * p
    off = 0.5 * prm["cell"]
    moat = prm["moat"] * w
    holes = []
    n = int(D / p) + 4
    for i in range(-n, n + 1):
        for j in range(-n, n + 1):
            x, y = c + (i + off) * p, hy + (j + off) * p
            limit = D - (2 + prm["ring"]) * w if prm["ring"] > 0 else D - prm["rim"] * w
            if math.hypot(x - c, y - c) + r > limit + 1e-6:
                continue
            if dist_to_keyhole(x, y, c, hy, R, s, L) - r < moat - 1e-6:
                continue
            holes.append((x, y))
    kh = keyhole_path(c, hy, R, s, L, prm["fillet"] * r)
    if prm["mode"] == 1:
        d = [circle_path(x, y, r) for x, y in holes] + [kh]
    elif prm["mode"] == 2:
        # Kleinformat (16/32 px): gleiche Scheibe, gleiches Schluesselloch, ohne Gitter und Ring
        d = [circle_path(c, c, D), kh]
    else:
        d = [circle_path(c, c, D)]
        if prm["ring"] > 0:
            # Gravurring: aussen genau eine Stegbreite Rand, innen genau eine Stegbreite bis zu den Loechern
            rw = prm["ring"] * w
            ro = D - w
            d += [circle_path(c, c, ro), circle_path(c, c, ro - rw)]
        d += [circle_path(x, y, r) for x, y in holes]
        d.append(kh)
    geo = dict(r=r, w=w, R=R, s=s, L=L, hy=hy, holes=len(holes),
               kh_top=hy - R, kh_bot=hy + L + s, kh_mid=(hy - R + hy + L + s) / 2)
    return "".join(d), geo


# --- Squircle (kontinuierliche Ecke, Apple-Konstanten) ---
def squircle_path(x, y, w, h, r):
    k = [1.52866483, 1.08849323, 0.86840689, 0.63149399, 0.07491100,
         0.37282392, 0.16905899]
    a, b, cc, d, e, f, g = [v * r for v in k]
    X0, Y0, X1, Y1 = x, y, x + w, y + h
    P_ = []
    P_.append(f"M{fmt(X0 + a)} {fmt(Y0)}")
    P_.append(f"L{fmt(X1 - a)} {fmt(Y0)}")
    P_.append(f"C{fmt(X1 - b)} {fmt(Y0)} {fmt(X1 - cc)} {fmt(Y0)} {fmt(X1 - d)} {fmt(Y0 + e)}")
    P_.append(f"C{fmt(X1 - f)} {fmt(Y0 + g)} {fmt(X1 - g)} {fmt(Y0 + f)} {fmt(X1 - e)} {fmt(Y0 + d)}")
    P_.append(f"C{fmt(X1)} {fmt(Y0 + cc)} {fmt(X1)} {fmt(Y0 + b)} {fmt(X1)} {fmt(Y0 + a)}")
    P_.append(f"L{fmt(X1)} {fmt(Y1 - a)}")
    P_.append(f"C{fmt(X1)} {fmt(Y1 - b)} {fmt(X1)} {fmt(Y1 - cc)} {fmt(X1 - e)} {fmt(Y1 - d)}")
    P_.append(f"C{fmt(X1 - g)} {fmt(Y1 - f)} {fmt(X1 - f)} {fmt(Y1 - g)} {fmt(X1 - d)} {fmt(Y1 - e)}")
    P_.append(f"C{fmt(X1 - cc)} {fmt(Y1)} {fmt(X1 - b)} {fmt(Y1)} {fmt(X1 - a)} {fmt(Y1)}")
    P_.append(f"L{fmt(X0 + a)} {fmt(Y1)}")
    P_.append(f"C{fmt(X0 + b)} {fmt(Y1)} {fmt(X0 + cc)} {fmt(Y1)} {fmt(X0 + d)} {fmt(Y1 - e)}")
    P_.append(f"C{fmt(X0 + f)} {fmt(Y1 - g)} {fmt(X0 + g)} {fmt(Y1 - f)} {fmt(X0 + e)} {fmt(Y1 - d)}")
    P_.append(f"C{fmt(X0)} {fmt(Y1 - cc)} {fmt(X0)} {fmt(Y1 - b)} {fmt(X0)} {fmt(Y1 - a)}")
    P_.append(f"L{fmt(X0)} {fmt(Y0 + a)}")
    P_.append(f"C{fmt(X0)} {fmt(Y0 + b)} {fmt(X0)} {fmt(Y0 + cc)} {fmt(X0 + e)} {fmt(Y0 + d)}")
    P_.append(f"C{fmt(X0 + g)} {fmt(Y0 + f)} {fmt(X0 + f)} {fmt(Y0 + g)} {fmt(X0 + d)} {fmt(Y0 + e)}")
    P_.append(f"C{fmt(X0 + cc)} {fmt(Y0)} {fmt(X0 + b)} {fmt(Y0)} {fmt(X0 + a)} {fmt(Y0)}Z")
    return "".join(P_)


def build(out, prm, mark_name="mark.svg", icon_name="icon.svg"):
    os.makedirs(out, exist_ok=True)
    d, geo = build_mark(prm)
    mark = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">\n'
        '  <!-- Siegel, Entwurf 02 "Gitter": Siegelscheibe mit Lochgitter, Schluesselloch aus dem Gitter verschmolzen -->\n'
        f'  <path fill="#000000" fill-rule="evenodd" d="{d}"/>\n'
        '</svg>\n')
    if mark_name:
        with open(os.path.join(out, mark_name), "w") as fh:
            fh.write(mark)

    sc = prm["icon_scale"]
    tx = 512 - 512 * sc
    ty = 512 - 512 * sc + prm["icon_dy"]
    body = squircle_path(100, 100, 824, 824, 185.4)
    shadow = ""
    if prm["shadow"]:
        layers = []
        # weicher Schlagschatten: gestapelte, leicht vergroesserte Koerper mit geringer Deckkraft
        for k in range(8, 0, -1):
            g = k * 2.6
            layers.append(
                f'    <path opacity="0.026" d="{squircle_path(100 - g, 100 - g + 10, 824 + 2 * g, 824 + 2 * g, 185.4 + g)}"/>')
        shadow = '  <g fill="#000000">\n' + "\n".join(layers) + "\n  </g>\n"
    icon = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">\n'
        '  <!-- Siegel – macOS-App-Icon, Entwurf 02 "Gitter" -->\n'
        + shadow +
        f'  <path fill="#FFFFFF" d="{body}"/>\n'
        f'  <g transform="translate({fmt(tx)} {fmt(ty)}) scale({sc})">\n'
        f'    <path fill="#000000" fill-rule="evenodd" d="{d}"/>\n'
        '  </g>\n'
        '</svg>\n')
    with open(os.path.join(out, icon_name), "w") as fh:
        fh.write(icon)
    return geo


if __name__ == "__main__":
    args = sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))
    out = args.pop(0) if args and "=" not in args[0] else here
    prm = dict(P)
    for a in args:
        k, v = a.split("=")
        prm[k] = int(float(v)) if isinstance(P[k], int) else float(v)
    geo = build(out, prm)
    print({k: (round(v, 2) if isinstance(v, float) else v) for k, v in geo.items()})
    if prm["mode"] == 0:
        # Kleinformat fuer die iconset-Slots 16 px und 32 px (optional, wie Apple es bei kleinen Groessen macht)
        build(out, dict(prm, mode=2), None, "icon-klein.svg")
