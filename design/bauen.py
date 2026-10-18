#!/usr/bin/env python3
"""Siegel – Bildmarke «Schlüssel-S», Feinschliff vom 16.10.2026. Quelle der Wahrheit.

Schreibt:
  logo.svg           Zeichen mit enger viewBox (0 0 22 22, Koordinaten = Einheiten u), für die App
  icon-ebene.svg     Icon-Composer-Ebene: schwarzes Zeichen auf transparent, viewBox 0 0 1024 1024
  icon-vorschau.svg  nur zur Ansicht: weisser Squircle 824 bei (100,100) + Ebene, ohne Schatten
  render/*.png       Prüfbilder (falls der SVG-Renderer da ist), vorher-nachher.png (falls Pillow da ist)
  SiegelMark.swift   nur der Massblock (MASS-ANFANG … MASS-ENDE) wird nachgeführt

Konstruktion (Einheit u, Mittelpunkt 0/0, y nach unten wie in SVG):
  - Scheibe Ø 21 u, senkrecht geteilt 5 · 3 · 5 · 3 · 5 (drei Bänder, zwei Schlitze)
  - Schlitzachsen bei y = −4 u (oben, läuft nach rechts aus) und y = +4 u (unten, nach links)
  - Schlüssellochkopf Ø 6 u = 2 × Schlitz, Kopfmitten (−2.5 u, −4 u) und (+2.5 u, +4 u)
  - Hals scharf (keine Ausrundung), Schlitz gerade (kein Keil), siehe LOGO.md
  - punktsymmetrisch: der untere Teil ist der obere, um 180° gedreht

Massänderungen NUR hier in MASS / U_ICON vornehmen, dann neu bauen. Nie im SVG von Hand editieren.

Aufruf:  python3 bauen.py              (Pillow ist optional, nur für vorher-nachher.png nötig;
                                       Python.org 3.12 hat es: /Library/Frameworks/.../3.12/bin/python3)
Renderer: Umgebungsvariable SVG_RENDER oder werkzeuge/bin/svg_render (wird aus skripte/svg_render.swift
übersetzt). SiegelMark.swift: der Block zwischen MASS-ANFANG und MASS-ENDE wird hier nachgeführt.
Prüfung am echten System-Icon (actool + macOS-Renderer): werkzeuge/systemtest.py.
"""
import math
import os
import subprocess

HIER = os.path.dirname(os.path.abspath(__file__))
PROJEKT = os.path.dirname(HIER)
# SVG-Renderer: SVG_RENDER, sonst das eigene Binary in werkzeuge/bin (wird bei Bedarf aus
# skripte/svg_render.swift übersetzt, derselbe macOS-Renderer wie in der App).
RENDER = os.environ.get("SVG_RENDER", os.path.join(HIER, "werkzeuge", "bin", "svg_render"))

# ---- Masse (Einheit u) ------------------------------------------------------------------------
MASS = dict(
    R=10.5,        # Scheibenradius (Ø 21 u)
    schlitz=3.0,   # Schlitzbreite (in der Schlitzmitte, falls keil > 0)
    ky=4.0,        # Schlitzachse bei y = ∓4 u
    rk=3.0,        # Radius Schlüssellochkopf (Ø 6 u = 2 × Schlitz)
    kx=2.5,        # Kopfmitte bei x = ∓2.5 u
    keil=0.0,      # Verbreiterung des Schlitzes zur Mündung hin, volle Breite pro u Länge (0 = gerade)
    hals=0.0,      # Ausrundung am Hals Schlitz/Kopf in u (0 = scharf)
    spitze=0.0,    # Ausrundung der spitzen S-Enden an der Schlitzmündung in u (0 = scharf)
    hub=3.0,       # Riegelweg in u bei riegel = 1 (Entsperr-Animation, nur SwiftUI)
)

# Stand des Wettbewerbs (Entwurf 03) – nur für vorher-nachher.png
MASS_ALT = dict(MASS, rk=2.5, kx=3.0)
U_ALT = 23

U_ICON = 24            # u im fertigen 1024er-Icon: Scheibe 504 px = 61.2 % des 824er-Körpers;
                       # Schlitzkanten liegen bei 16 px nur 1/16 px, bei 32 px 1/8 px neben dem Raster
LOGO_RAND = 0.5        # Rand der engen viewBox in u (viewBox 22 × 22 u)
KOERPER = (100, 100, 824, 185)   # System-Squircle im fertigen 1024er-Icon (x, y, Seite, Eckradius)
# Icon Composer / actool legen die 1024er-Leinwand der Ebene auf den ganzen Körper (824 px), nicht 1:1 auf
# das 1024er-Icon. Gemessen am 16.10.2026 mit actool (Xcode 27): Ebene mit Scheibe 504 px -> im Icon nur
# 406 px. Darum wird die Ebene um 1024/824 grösser gebaut, damit im fertigen Icon u = U_ICON gilt.
EBENE_SKALA = 1024 / KOERPER[2]


# ---- Geometrie --------------------------------------------------------------------------------
def _schnitt(p0, d, m, r):
    """Parameter t der Schnittpunkte der Geraden p0 + t·d mit dem Kreis (m, r), aufsteigend."""
    fx, fy = p0[0] - m[0], p0[1] - m[1]
    a = d[0] ** 2 + d[1] ** 2
    b = 2 * (fx * d[0] + fy * d[1])
    c = fx * fx + fy * fy - r * r
    disk = b * b - 4 * a * c
    if disk < 0:
        raise ValueError("kein Schnittpunkt – Masse prüfen")
    s = math.sqrt(disk)
    return sorted(((-b - s) / (2 * a), (-b + s) / (2 * a)))


def _winkel(p, m=(0.0, 0.0)):
    return math.degrees(math.atan2(p[1] - m[1], p[0] - m[0]))


def _kurz(a0, a1):
    """Kürzester Bogen von a0 nach a1 (Grad): Endwinkel so gewählt, dass |a1 − a0| < 180."""
    d = (a1 - a0 + 180) % 360 - 180
    return a0 + d


def umweg_oben(M, riegel=0.0):
    """Kontur entlang des oberen Schlüssellochs (Schlitz läuft nach rechts aus).

    Liefert (Startwinkel am Scheibenrand, Segmente, Endwinkel am Scheibenrand).
    Segmente: ("L", (x, y)) oder ("A", (mx, my), r, a0, a1)  – a1 < a0 heisst gegen den Uhrzeigersinn
    auf dem Bildschirm (y nach unten). Einheiten u, Scheibenmitte 0/0."""
    R, w, ky, rk, kx = M["R"], M["schlitz"], M["ky"], M["rk"], M["kx"]
    H = (-kx + M["hub"] * riegel, -ky)                       # Kopfmitte
    # Schlitzmitte (für den Keil): Mitte zwischen Hals und Mündung, in Ruhelage gemessen
    d_hals = math.sqrt(rk * rk - (w / 2) ** 2)
    d_rand = math.sqrt(R * R - ky * ky) + kx
    xm = H[0] + (d_hals + d_rand) / 2

    kanten = {}
    for s in (-1, 1):                                           # −1 = Oberkante, +1 = Unterkante
        d = (1.0, s * M["keil"] / 2)
        n_ = math.hypot(*d)
        d = (d[0] / n_, d[1] / n_)                              # Richtung zur Mündung
        q = (xm, -ky + s * w / 2)                               # Punkt auf der Kante
        n = (s * -d[1], s * d[0])                               # Normale ins Schwarze (weg vom Schlitz)
        kanten[s] = (q, d, n)

    def pkt(q, d, t):
        return (q[0] + t * d[0], q[1] + t * d[1])

    seg = []
    # Oberkante: Mündung (spitzes S-Ende) -> Hals
    q, d, n = kanten[-1]
    E_o = pkt(q, d, _schnitt(q, d, (0, 0), R)[1])
    rt = M["spitze"]
    if rt > 0:
        qq = (q[0] + rt * n[0], q[1] + rt * n[1])
        t = _schnitt(qq, d, (0, 0), R - rt)[1]
        F = pkt(qq, d, t)
        T_rand = (F[0] * R / math.hypot(*F), F[1] * R / math.hypot(*F))
        T_kante = pkt(q, d, t)
        start = _winkel(T_rand)
        a0 = _winkel(T_rand, F)
        seg.append(("A", F, rt, a0, _kurz(a0, _winkel(T_kante, F))))
    else:
        start = _winkel(E_o)

    def hals(s):
        """Übergang Kante s -> Kopf: (Punkt auf Kante, Punkt auf Kopf, Ausrundungsmitte oder None)."""
        q, d, n = kanten[s]
        rf = M["hals"]
        if rf > 0:
            qq = (q[0] + rf * n[0], q[1] + rf * n[1])
            t = _schnitt(qq, d, H, rk + rf)[1]
            F = pkt(qq, d, t)
            dist = math.hypot(F[0] - H[0], F[1] - H[1])
            T_kopf = (H[0] + rk * (F[0] - H[0]) / dist, H[1] + rk * (F[1] - H[1]) / dist)
            return pkt(q, d, t), T_kopf, F
        N = pkt(q, d, _schnitt(q, d, H, rk)[1])
        return N, N, None

    L_o, K_o, F_o = hals(-1)
    L_u, K_u, F_u = hals(1)
    rf = M["hals"]
    seg.append(("L", L_o))
    if F_o:
        a0 = _winkel(L_o, F_o)
        seg.append(("A", F_o, rf, a0, _kurz(a0, _winkel(K_o, F_o))))
    a0 = _winkel(K_o, H)
    a1 = _winkel(K_u, H)
    a1 = a0 - ((a0 - a1) % 360)                                 # langer Weg um den Kopf, gegen Uhrzeigersinn
    seg.append(("A", H, rk, a0, a1))
    if F_u:
        a0 = _winkel(K_u, F_u)
        seg.append(("A", F_u, rf, a0, _kurz(a0, _winkel(L_u, F_u))))
    q, d, n = kanten[1]
    E_u = pkt(q, d, _schnitt(q, d, (0, 0), R)[1])
    seg.append(("L", E_u))
    return start % 360, seg, _winkel(E_u) % 360


def _drehen(seg):
    """Um 180° um die Scheibenmitte drehen (Punktsymmetrie)."""
    out = []
    for s in seg:
        if s[0] == "L":
            out.append(("L", (-s[1][0], -s[1][1])))
        else:
            _, F, r, a0, a1 = s
            out.append(("A", (-F[0], -F[1]), r, a0 + 180, a1 + 180))
    return out


def kontur(M=MASS, riegel=0.0):
    """Ganze Kontur als ein geschlossener Zug: Liste von ("M", p) / ("L", p) / ("A", m, r, a0, a1)."""
    R = M["R"]
    a_s, seg, a_e = umweg_oben(M, riegel)
    while a_s < 270:
        a_s += 360
    while a_e < a_s:
        a_e += 360
    out = [("M", (0.0, -R)), ("A", (0.0, 0.0), R, 270.0, a_s)]
    out += seg
    out.append(("A", (0.0, 0.0), R, a_e, a_s + 180))
    out += _drehen(seg)
    out.append(("A", (0.0, 0.0), R, a_e + 180, 630.0))
    return out


# ---- SVG --------------------------------------------------------------------------------------
def zahl(v, stellen=2):
    s = f"{v:.{stellen}f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def svg_pfad(u, cx, cy, M=MASS, riegel=0.0, stellen=2):
    """SVG-Pfad (d) des Zeichens mit Einheit u und Mitte (cx, cy). Bögen in Stücken <= 90°."""
    z = lambda v: zahl(v, stellen)
    d, cur = [], None
    for s in kontur(M, riegel):
        if s[0] == "M":
            cur = (cx + u * s[1][0], cy + u * s[1][1])
            d.append(f"M{z(cur[0])} {z(cur[1])}")
        elif s[0] == "L":
            p = (cx + u * s[1][0], cy + u * s[1][1])
            if abs(p[1] - cur[1]) < 1e-9:
                d.append(f"H{z(p[0])}")
            elif abs(p[0] - cur[0]) < 1e-9:
                d.append(f"V{z(p[1])}")
            else:
                d.append(f"L{z(p[0])} {z(p[1])}")
            cur = p
        else:
            _, F, r, a0, a1 = s
            n = max(1, math.ceil(abs(a1 - a0) / 90 - 1e-9))
            for i in range(1, n + 1):
                a = math.radians(a0 + (a1 - a0) * i / n)
                p = (cx + u * (F[0] + r * math.cos(a)), cy + u * (F[1] + r * math.sin(a)))
                d.append(f"A{z(u * r)} {z(u * r)} 0 0 {1 if a1 > a0 else 0} {z(p[0])} {z(p[1])}")
                cur = p
    d.append("Z")
    return "".join(d)


def squircle(x, y, s, r):
    """Quadrat mit kontinuierlicher Eckkrümmung (Apple-Rundung, Bézier-Näherung)."""
    a, b, c, dd, e, g, hh = [v * r for v in
                             (1.52866483, 1.08849323, 0.86840689, 0.66993427, 0.06549600, 0.37196778, 0.16496403)]
    X0, Y0, X1, Y1 = x, y, x + s, y + s
    z = zahl
    pts = [
        f"M{z(X0 + a)} {z(Y0)}", f"H{z(X1 - a)}",
        f"C{z(X1 - b)} {z(Y0)} {z(X1 - c)} {z(Y0)} {z(X1 - dd)} {z(Y0 + e)}",
        f"C{z(X1 - g)} {z(Y0 + hh)} {z(X1 - hh)} {z(Y0 + g)} {z(X1 - e)} {z(Y0 + dd)}",
        f"C{z(X1)} {z(Y0 + c)} {z(X1)} {z(Y0 + b)} {z(X1)} {z(Y0 + a)}", f"V{z(Y1 - a)}",
        f"C{z(X1)} {z(Y1 - b)} {z(X1)} {z(Y1 - c)} {z(X1 - e)} {z(Y1 - dd)}",
        f"C{z(X1 - hh)} {z(Y1 - g)} {z(X1 - g)} {z(Y1 - hh)} {z(X1 - dd)} {z(Y1 - e)}",
        f"C{z(X1 - c)} {z(Y1)} {z(X1 - b)} {z(Y1)} {z(X1 - a)} {z(Y1)}", f"H{z(X0 + a)}",
        f"C{z(X0 + b)} {z(Y1)} {z(X0 + c)} {z(Y1)} {z(X0 + dd)} {z(Y1 - e)}",
        f"C{z(X0 + g)} {z(Y1 - hh)} {z(X0 + hh)} {z(Y1 - g)} {z(X0 + e)} {z(Y1 - dd)}",
        f"C{z(X0)} {z(Y1 - c)} {z(X0)} {z(Y1 - b)} {z(X0)} {z(Y1 - a)}", f"V{z(Y0 + a)}",
        f"C{z(X0)} {z(Y0 + b)} {z(X0)} {z(Y0 + c)} {z(X0 + e)} {z(Y0 + dd)}",
        f"C{z(X0 + hh)} {z(Y0 + g)} {z(X0 + g)} {z(Y0 + hh)} {z(X0 + dd)} {z(Y0 + e)}",
        f"C{z(X0 + c)} {z(Y0)} {z(X0 + b)} {z(Y0)} {z(X0 + a)} {z(Y0)}", "Z",
    ]
    return "".join(pts)


def logo_svg(M=MASS, riegel=0.0):
    seite = 2 * (M["R"] + LOGO_RAND)
    m = seite / 2
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {zahl(seite)} {zahl(seite)}">\n'
            f'  <path d="{svg_pfad(1.0, m, m, M, riegel, stellen=4)}" fill="#000"/>\n'
            '</svg>\n')


def ebene_pfad(M=MASS, u=U_ICON):
    """Pfad in Ebenen-Koordinaten (1024er-Leinwand = Körper)."""
    return svg_pfad(u * EBENE_SKALA, 512, 512, M)


def icon_ebene_svg(M=MASS, u=U_ICON):
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">\n'
            f'  <path d="{ebene_pfad(M, u)}" fill="#000"/>\n'
            '</svg>\n')


def icon_vorschau_svg(M=MASS, u=U_ICON):
    """Weisser Körper + Ebene, so abgebildet wie es das System tut (Leinwand -> Körper). Ohne Schatten."""
    x, y, s, r = KOERPER
    k = s / 1024
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">\n'
            f'  <path d="{squircle(x, y, s, r)}" fill="#fff"/>\n'
            f'  <g transform="translate({zahl(x)} {zahl(y)}) scale({k:.7g})">\n'
            f'    <path d="{ebene_pfad(M, u)}" fill="#000"/>\n'
            '  </g>\n'
            '</svg>\n')


# ---- Rendern ----------------------------------------------------------------------------------
def renderer():
    """Pfad zum SVG-Renderer; übersetzt skripte/svg_render.swift, falls das Binary fehlt."""
    if os.path.exists(RENDER):
        return RENDER
    quelle = os.path.join(PROJEKT, "skripte", "svg_render.swift")
    if "SVG_RENDER" in os.environ or not os.path.exists(quelle):
        return None
    os.makedirs(os.path.dirname(RENDER), exist_ok=True)
    env = dict(os.environ)
    if os.path.isdir("/Applications/Xcode.app"):
        env.setdefault("DEVELOPER_DIR", "/Applications/Xcode.app/Contents/Developer")
    r = subprocess.run(["xcrun", "swiftc", "-O", "-o", RENDER, quelle], env=env)
    return RENDER if r.returncode == 0 else None


def rendern(svg, png, px, bg):
    subprocess.run([renderer(), svg, png, str(px), bg], check=True, stdout=subprocess.DEVNULL)


# ---- SwiftUI-Shape nachführen -----------------------------------------------------------------
def swift_nachfuehren(M=MASS):
    """Schreibt die Masse in den Block MASS-ANFANG … MASS-ENDE von SiegelMark.swift."""
    pfad = os.path.join(HIER, "SiegelMark.swift")
    if not os.path.exists(pfad):
        return
    if M["keil"] or M["hals"] or M["spitze"]:
        print("ACHTUNG: SiegelMark.swift kennt keil/hals/spitze nicht – Shape von Hand erweitern!")
    zeilen = [
        f"    static let r: CGFloat = {zahl(M['R'], 4)}        // Scheibenradius in u",
        f"    static let schlitz: CGFloat = {zahl(M['schlitz'], 4)}     // Schlitzbreite in u",
        f"    static let ky: CGFloat = {zahl(M['ky'], 4)}          // Schlitzachse bei y = ∓ky",
        f"    static let rk: CGFloat = {zahl(M['rk'], 4)}          // Radius Schlüssellochkopf",
        f"    static let kx: CGFloat = {zahl(M['kx'], 4)}        // Kopfmitte bei x = ∓kx",
        f"    static let hub: CGFloat = {zahl(M['hub'], 4)}         // Riegelweg bei riegel = 1",
    ]
    text = open(pfad).read()
    a = text.index("// MASS-ANFANG")
    a = text.index("\n", a) + 1
    e = text.index("    // MASS-ENDE")
    neu = text[:a] + "\n".join(zeilen) + "\n" + text[e:]
    if neu != text:
        open(pfad, "w").write(neu)
        print("SiegelMark.swift: Masse nachgeführt")


# ---- Prüfungen --------------------------------------------------------------------------------
def kleinformat_pruefung(M=MASS, u=U_ICON):
    """Lage der Schlitzkanten bei 1:1-Rasterung des Icons (Körper 824/1024 wie in icon-vorschau):
    Abstand der vier Kanten zur nächsten Pixelgrenze. Das System rendert 16 pt mit grösserem Körper und
    Glas-Effekt (siehe werkzeuge/systemtest.py); diese Zahlen gelten für die reine Vektor-Rasterung."""
    zeilen = []
    for px in (16, 32, 64, 128):
        s = px / 1024
        kanten = [512 + k * u for k in (-(M["ky"] + M["schlitz"] / 2), -(M["ky"] - M["schlitz"] / 2),
                                        M["ky"] - M["schlitz"] / 2, M["ky"] + M["schlitz"] / 2)]
        abw = [abs(k * s - round(k * s)) for k in kanten]
        zeilen.append(f"  {px:>4} px: Schlitz {3 * u * s:.3f} px, Kantenabstand zum Raster "
                      + " ".join(f"{a:.3f}" for a in abw))
    print("Kleinformate (1:1-Rasterung):\n" + "\n".join(zeilen))


def vorher_nachher(render_dir):
    """Wettbewerbsstand (Entwurf 03) und Feinschliff nebeneinander. Braucht Pillow."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        print("Pillow fehlt – vorher-nachher.png übersprungen (mit Python.org 3.12 aufrufen)")
        return
    import tempfile
    try:
        schrift = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 22)
        klein = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 15)
    except OSError:
        schrift = klein = ImageFont.load_default()
    tmp = tempfile.mkdtemp(prefix="siegel-vn-")
    spalten = [("Vorher: Wettbewerb 03", "Kopf Ø 5 u bei (±3, ±4) · Icon u 23 (58.6 %)", MASS_ALT, U_ALT),
               ("Nachher: Feinschliff", "Kopf Ø 6 u bei (±2.5, ±4) · Icon u 24 (61.2 %)", MASS, U_ICON)]
    W, B = 1180, 560
    H = 60 + 420 + 20 + 512 + 30 + 140 + 30
    img = Image.new("RGB", (W, H), (237, 237, 237))
    dr = ImageDraw.Draw(img)
    for i, (titel, unter, M, u) in enumerate(spalten):
        sv = os.path.join(tmp, f"{i}-icon.svg")
        open(sv, "w").write(icon_vorschau_svg(M, u))
        lg = os.path.join(tmp, f"{i}-logo.svg")
        open(lg, "w").write(logo_svg(M))
        b = {}
        for px in (512, 128, 32, 16):
            p = os.path.join(tmp, f"{i}-{px}.png")
            rendern(sv, p, px, "#EDEDED")
            b[px] = Image.open(p).convert("RGB")
        p = os.path.join(tmp, f"{i}-logo.png")
        rendern(lg, p, 420, "white")
        b["logo"] = Image.open(p).convert("RGB")
        x0 = 20 + i * (B + 20)
        dr.text((x0, 14), titel, fill=(0, 0, 0), font=schrift)
        dr.text((x0, 40), unter, fill=(110, 110, 110), font=klein)
        dr.rectangle((x0, 60, x0 + B - 1, 60 + 420 - 1), fill=(255, 255, 255))
        img.paste(b["logo"], (x0 + (B - 420) // 2, 60))
        img.paste(b[512], (x0 + (B - 512) // 2, 60 + 420 + 20))
        y = 60 + 420 + 20 + 512 + 30
        img.paste(b[128], (x0, y))
        img.paste(b[32].resize((128, 128), Image.NEAREST), (x0 + 150, y))
        img.paste(b[16].resize((128, 128), Image.NEAREST), (x0 + 300, y))
        img.paste(b[32], (x0 + 460, y + 48))
        img.paste(b[16], (x0 + 512, y + 56))
        dr.text((x0, y + 134), "128 px        32 px (×4)          16 px (×8)           32 · 16 px", fill=(110, 110, 110), font=klein)
    dr.line((W // 2, 14, W // 2, H - 14), fill=(190, 190, 190), width=2)
    img.save(os.path.join(render_dir, "vorher-nachher.png"))


def konstruktion(render_dir, M=MASS):
    """Konstruktionszeichnung in u (Raster, Kreise, Mitten, Teilung). Braucht Pillow."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return
    try:
        f = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 20)
        fk = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 16)
    except OSError:
        f = fk = ImageFont.load_default()
    k = 2                                   # Überabtastung für glatte Linien
    E, W = 44 * k, 1200 * k                 # u in px, Bildgrösse
    cx, cy = 640 * k, 600 * k
    img = Image.new("RGB", (W, W), (255, 255, 255))
    d = ImageDraw.Draw(img)
    P = lambda x, y: (cx + x * E, cy + y * E)
    R = M["R"]
    # Raster 1 u
    for i in range(-12, 13):
        d.line([P(i, -12), P(i, 12)], fill=(236, 236, 236), width=k)
        d.line([P(-12, i), P(12, i)], fill=(236, 236, 236), width=k)
    # Zeichen als Fläche (Bögen fein unterteilt)
    pts = []
    for sg in kontur(M):
        if sg[0] in ("M", "L"):
            pts.append(P(*sg[1]))
        else:
            _, F, r, a0, a1 = sg
            n = max(2, int(abs(a1 - a0)))
            for i in range(1, n + 1):
                a = math.radians(a0 + (a1 - a0) * i / n)
                pts.append(P(F[0] + r * math.cos(a), F[1] + r * math.sin(a)))
    d.polygon(pts, fill=(215, 215, 215))
    # Teilung 5 · 3 · 5 · 3 · 5
    h = M["schlitz"] / 2
    for y in (-(M["ky"] + h), -(M["ky"] - h), M["ky"] - h, M["ky"] + h):
        d.line([P(-12, y), P(12, y)], fill=(0, 0, 0), width=k)
    for y in (-R, R):
        d.line([P(-12, y), P(0, y)], fill=(150, 150, 150), width=k)
    # Kreise: Scheibe, Köpfe, Mitten
    def kreis(x, y, r, w=2):
        d.ellipse([P(x - r, y - r), P(x + r, y + r)], outline=(0, 0, 0), width=w * k)
    def kreuz(x, y):
        d.line([P(x - .4, y), P(x + .4, y)], fill=(0, 0, 0), width=2 * k)
        d.line([P(x, y - .4), P(x, y + .4)], fill=(0, 0, 0), width=2 * k)
    kreis(0, 0, R)
    for s in (1, -1):
        kreis(-s * M["kx"], -s * M["ky"], M["rk"])
        kreuz(-s * M["kx"], -s * M["ky"])
        d.line([P(0, 0), P(-s * M["kx"], -s * M["ky"])], fill=(120, 120, 120), width=k)
    kreuz(0, 0)
    d.line([P(0, -12), P(0, 12)], fill=(150, 150, 150), width=k)
    # Beschriftung (auf Originalgrösse zurückrechnen)
    img = img.resize((W // k, W // k), Image.LANCZOS)
    d = ImageDraw.Draw(img)
    Q = lambda x, y: (cx / k + x * E / k, cy / k + y * E / k)
    def text(x, y, t, ft=f, anker="la"):
        d.text(Q(x, y), t, fill=(0, 0, 0), font=ft, anchor=anker)
    # Massketten links
    grenzen = [-R, -(M["ky"] + h), -(M["ky"] - h), M["ky"] - h, M["ky"] + h, R]
    for a, b in zip(grenzen, grenzen[1:]):
        text(-12.6, (a + b) / 2, f"{zahl(b - a)} u", anker="rm")
    text(-12.6, -11.4, "Teilung", fk, "rm")
    sx, sy = math.sqrt(R * R - (M["ky"] + h) ** 2), -(M["ky"] + h)
    text(0.4, -11.2, f"Scheibe Ø {zahl(2 * R)} u, Mitte (0, 0)", fk)
    text(-M["kx"] - 4.3, -M["ky"] - 3.6, f"Kopf Ø {zahl(2 * M['rk'])} u", fk)
    text(-M["kx"] - 4.3, -M["ky"] - 3.0, f"Mitte (−{zahl(M['kx'])}, −{zahl(M['ky'])})", fk)
    text(M["kx"] + 0.6, M["ky"] + 3.3, f"Mitte ({zahl(M['kx'])}, {zahl(M['ky'])})", fk)
    hx = -M["kx"] + math.sqrt(M["rk"] ** 2 - h * h)
    text(hx + 0.3, -(M["ky"] - h) + 0.25, f"Hals x = {hx:.2f} u, 30°", fk)
    spitze = 90 - math.degrees(math.asin(-sy / R))
    text(sx - 4.6, sy - 1.5, f"Mündung x = √{zahl(R * R - sy * sy)} = {sx:.2f} u", fk)
    text(sx - 4.6, sy - 0.9, f"spitzes S-Ende {spitze:.1f}°", fk)
    ring = R - M["rk"] - math.hypot(M["kx"], M["ky"])
    ruecken = 2 * math.hypot(M["kx"], M["ky"]) - 2 * M["rk"]
    text(-12, 11.6, f"Ring Kopf–Rand min. {ring:.2f} u · Rücken zwischen den Köpfen min. {ruecken:.2f} u · "
                    "Schlitz 3 u · Bänder 5 u", fk)
    text(-12, 12.2, "Punktsymmetrisch: die untere Hälfte ist die obere, um 180° gedreht.", fk)
    img.save(os.path.join(render_dir, "konstruktion.png"))


def main():
    pfade = {
        "logo.svg": logo_svg(),
        "icon-ebene.svg": icon_ebene_svg(),
        "icon-vorschau.svg": icon_vorschau_svg(),
    }
    for name, inhalt in pfade.items():
        open(os.path.join(HIER, name), "w").write(inhalt)
    swift_nachfuehren()
    kleinformat_pruefung()
    if not renderer():
        print("SVGs geschrieben; kein SVG-Renderer gefunden:", RENDER)
        return
    rd = os.path.join(HIER, "render")
    os.makedirs(rd, exist_ok=True)
    for px in (1024, 512, 128, 64, 32, 16):
        rendern(os.path.join(HIER, "icon-vorschau.svg"), os.path.join(rd, f"icon-{px}.png"), px, "#EDEDED")
    for px in (176, 512):
        rendern(os.path.join(HIER, "logo.svg"), os.path.join(rd, f"logo-{px}.png"), px, "white")
    vorher_nachher(rd)
    konstruktion(rd)
    print("SVGs und Renders geschrieben:", HIER)


if __name__ == "__main__":
    main()
