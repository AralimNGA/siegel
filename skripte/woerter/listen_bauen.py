#!/usr/bin/env python3
"""Baut die Wortlisten der Passwort-Schätzung (SPEC §1.6) als Swift-Quelldateien.

Aufruf (aus dem Paketordner):  python3 skripte/woerter/listen_bauen.py
Eingaben:  skripte/woerter/quellen/*.txt, skripte/woerter/quellen/zxcvbn/*.txt, /usr/share/dict/web2
Ausgaben:  Sources/SiegelCore/Staerke/Woerter/Liste*.swift (je Liste EIN Raw-String-Literal)

Keine Downloads. Das Skript bricht ab, wenn die Passphrasen-Liste nicht genau 2048 gültige Wörter hat.
Herkunft und Lizenzen: Sources/SiegelCore/Staerke/Woerter/HERKUNFT.md
"""

import os
import re
import sys
import unicodedata

HIER = os.path.dirname(os.path.abspath(__file__))
PAKET = os.path.abspath(os.path.join(HIER, "..", ".."))
QUELLEN = os.path.join(HIER, "quellen")
ZXCVBN = os.path.join(QUELLEN, "zxcvbn")
ZIEL = os.path.join(PAKET, "Sources", "SiegelCore", "Staerke", "Woerter")
WEB2 = "/usr/share/dict/web2"

PASSPHRASE_ANZAHL = 2048
WEB2_MINDESTLAENGE = 6          # kürzere Wörter wären als Brute-Force (10^n) ohnehin billiger als Rang 150 000

# Wortstämme, die in Passphrasen nie vorkommen dürfen (Prüfung als Teilstring).
SPERRSTAEMME = [
    "arsch", "fick", "fotz", "hure", "nazi", "hitler", "sex", "porn", "nackt", "busen", "titt", "penis",
    "vagin", "kotz", "kack", "scheis", "pisse", "furz", "wichs", "schlampe", "nutte", "neger", "zigeun",
    "mord", "leiche", "toet", "folter", "bombe", "waffen", "gewehr", "pistol", "krieg", "terror", "drog",
    "kokain", "heroin", "teufel", "satan", "hoelle", "idiot", "depp", "trottel", "dumm", "doof", "bloed",
    "spast", "behindert", "schwuchtel", "tunte", "jude", "islam", "selbstmord", "suizid", "sarg",
]

# Umschriften ohne Umlaute (zuerst lang, dann kurz).
UMSCHRIFT_LANG = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss", "é": "e", "è": "e", "ê": "e", "à": "a",
                  "â": "a", "ç": "c", "ô": "o", "î": "i", "ï": "i", "ë": "e"}
UMSCHRIFT_KURZ = dict(UMSCHRIFT_LANG, **{"ä": "a", "ö": "o", "ü": "u"})


def fehler(text):
    sys.stderr.write("FEHLER: " + text + "\n")
    sys.exit(1)


# build.sh sperrt diese Zeichenfolgen in SiegelCore per grep (SPEC §5); Listeneinträge damit fallen weg.
GESPERRT_IM_QUELLTEXT = ["try!", "print(", "debugprint(", "dump(", "nslog(", "privacy: .public", "fatalerror(",
                         "precondition(", "assert(", "uniquekeyswithvalues"]


def sauber(wort):
    """NFC, klein, ohne Steuer- und Richtungszeichen; None, wenn unbrauchbar."""
    wort = unicodedata.normalize("NFC", wort.strip().lower())
    if not wort:
        return None
    if any(g in wort for g in GESPERRT_IM_QUELLTEXT):
        return None
    for ch in wort:
        cp = ord(ch)
        if cp < 0x21 or cp == 0x7F or 0x200E <= cp <= 0x200F or 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            return None
    return wort


def varianten(wort):
    """Original plus Umschriften und Fassung ohne Satzzeichen (gleicher Rang)."""
    result = [wort]
    for tabelle in (UMSCHRIFT_LANG, UMSCHRIFT_KURZ):
        v = "".join(tabelle.get(ch, ch) for ch in wort)
        if v not in result:
            result.append(v)
    for v in list(result):
        ohne = re.sub(r"[.\-' ]", "", v)
        if ohne and ohne not in result:
            result.append(ohne)
    return result


def lies_eigene(name):
    """Eigene Quelle: Kommentare mit #, Einträge durch Leerraum getrennt, Reihenfolge = Rang."""
    pfad = os.path.join(QUELLEN, name)
    eintraege, gesehen = [], set()
    with open(pfad, encoding="utf-8") as fh:
        for zeile in fh:
            if zeile.lstrip().startswith("#"):
                continue
            for roh in zeile.split():
                w = sauber(roh)
                if w and w not in gesehen:
                    gesehen.add(w)
                    eintraege.append(w)
    return eintraege


def lies_zxcvbn(name):
    pfad = os.path.join(ZXCVBN, name + ".txt")
    eintraege, gesehen = [], set()
    with open(pfad, encoding="utf-8") as fh:
        for zeile in fh:
            w = sauber(zeile)
            if w and "\t" not in w and w not in gesehen:
                gesehen.add(w)
                eintraege.append(w)
    return eintraege


def selten_und_kurz(wort, rang):
    """wie zxcvbn: ein Eintrag, der als Brute-Force billiger wäre, bringt nichts."""
    return rang >= 10 ** len(wort)


def mit_varianten(eintraege):
    """Zeilen 'wort\\tvariante…'; filtert seltene kurze Varianten (Rang = Position)."""
    zeilen = []
    for wort in eintraege:
        rang = len(zeilen) + 1
        vs = [v for v in varianten(wort) if not selten_und_kurz(v, rang)]
        if vs:
            zeilen.append("\t".join(vs))
    return zeilen


def ohne_varianten(eintraege):
    zeilen = []
    for wort in eintraege:
        if not selten_und_kurz(wort, len(zeilen) + 1):
            zeilen.append(wort)
    return zeilen


def front_kodiert(woerter):
    zeichen = "0123456789abcdefghijklmnopqrstuvwxyz"
    zeilen, vorher = [], ""
    for w in woerter:
        k = 0
        while k < len(vorher) and k < len(w) and k < 35 and vorher[k] == w[k]:
            k += 1
        zeilen.append(zeichen[k] + w[k:])
        vorher = w
    return zeilen


def swift_literal(zeilen):
    inhalt = "\n".join(zeilen)
    n = 1
    while ('"""' + "#" * n) in inhalt or ("\\" + "#" * n) in inhalt:
        n += 1
    rauten = "#" * n
    return rauten + '"""\n' + inhalt + '\n"""' + rauten


def schreibe_swift(datei, listen):
    teile = [
        "// GENERIERT von skripte/woerter/listen_bauen.py – nicht von Hand ändern.",
        "// Herkunft und Lizenzen: HERKUNFT.md in diesem Ordner.",
        "",
        "extension ZxcvbnListData {",
    ]
    for name, doku, zeilen in listen:
        teile.append("    /// " + doku + " (" + str(len(zeilen)) + " Zeilen)")
        teile.append("    static let " + name + ": String = " + swift_literal(zeilen))
        teile.append("")
    teile[-1] = "}"
    pfad = os.path.join(ZIEL, datei)
    with open(pfad, "w", encoding="utf-8") as fh:
        fh.write("\n".join(teile) + "\n")
    return os.path.getsize(pfad)


def pruefe_passphrase(woerter):
    if len(woerter) != PASSPHRASE_ANZAHL:
        fehler("Passphrasen-Liste hat %d statt %d Wörter" % (len(woerter), PASSPHRASE_ANZAHL))
    if len(set(woerter)) != len(woerter):
        fehler("Passphrasen-Liste enthält Doppelte")
    for w in woerter:
        if not re.fullmatch(r"[a-z]{4,8}", w):
            fehler("Passphrasen-Wort verletzt die Regeln (4–8 Zeichen a–z): " + w)
        for stamm in SPERRSTAEMME:
            if stamm in w:
                fehler("Passphrasen-Wort enthält gesperrten Stamm '%s': %s" % (stamm, w))


def main():
    if not os.path.isdir(ZIEL):
        os.makedirs(ZIEL)

    # zxcvbn (Dropbox, MIT): bereits nach Rang gefiltert und untereinander bereinigt
    z = {n: lies_zxcvbn(n) for n in
         ["passwords", "english_wikipedia", "us_tv_and_film", "surnames", "male_names", "female_names"]}

    passwoerter_de = mit_varianten(lies_eigene("passwoerter_de.txt"))
    woerter_de = mit_varianten(lies_eigene("woerter_de.txt"))
    vornamen = mit_varianten(lies_eigene("vornamen_ch_de.txt"))
    nachnamen = mit_varianten(lies_eigene("nachnamen_ch_de.txt"))
    orte = mit_varianten(lies_eigene("orte_vereine_ch.txt"))
    passphrase = lies_eigene("passphrase_de.txt")
    pruefe_passphrase(passphrase)

    bekannt = set()
    for liste in list(z.values()) + [passphrase]:
        bekannt.update(liste)
    for zeilen in (passwoerter_de, woerter_de, vornamen, nachnamen, orte):
        for zeile in zeilen:
            bekannt.update(zeile.split("\t"))

    web2 = set()
    if os.path.exists(WEB2):
        with open(WEB2, encoding="utf-8") as fh:
            for zeile in fh:
                w = zeile.strip().lower()
                if len(w) >= WEB2_MINDESTLAENGE and re.fullmatch(r"[a-z]+", w) and w not in bekannt:
                    web2.add(w)
    else:
        fehler(WEB2 + " fehlt (gehört zu macOS)")
    web2_zeilen = front_kodiert(sorted(web2))

    groessen = {}
    groessen["ListePasswoerter.swift"] = schreibe_swift("ListePasswoerter.swift", [
        ("passwords", "Häufige Passwörter international (zxcvbn passwords, nach Häufigkeit)",
         ohne_varianten(z["passwords"])),
        ("passwordsGerman", "Häufige Passwörter Deutschland/Schweiz (eigene Liste, nach Häufigkeit)",
         passwoerter_de),
    ])
    groessen["ListeEnglisch.swift"] = schreibe_swift("ListeEnglisch.swift", [
        ("englishWikipedia", "Englische Wörter nach Häufigkeit (zxcvbn english_wikipedia)",
         ohne_varianten(z["english_wikipedia"])),
        ("usTvAndFilm", "Englische Wörter aus Film/TV nach Häufigkeit (zxcvbn us_tv_and_film)",
         ohne_varianten(z["us_tv_and_film"])),
    ])
    groessen["ListeEnglischWeb2.swift"] = schreibe_swift("ListeEnglischWeb2.swift", [
        ("englishWeb2", "Zusätzliche englische Wörter aus /usr/share/dict/web2 (gemeinfrei), ab "
         + str(WEB2_MINDESTLAENGE) + " Buchstaben, vorn-komprimiert, uniformer Rang", web2_zeilen),
    ])
    groessen["ListeDeutsch.swift"] = schreibe_swift("ListeDeutsch.swift", [
        ("germanWords", "Deutsche Wörter nach Häufigkeit (eigene Liste, mit Umschriften)", woerter_de),
    ])
    groessen["ListeNamen.swift"] = schreibe_swift("ListeNamen.swift", [
        ("surnames", "Nachnamen USA (zxcvbn surnames, US-Volkszählung)", ohne_varianten(z["surnames"])),
        ("maleNames", "Männliche Vornamen USA (zxcvbn male_names)", ohne_varianten(z["male_names"])),
        ("femaleNames", "Weibliche Vornamen USA (zxcvbn female_names)", ohne_varianten(z["female_names"])),
        ("firstNamesCHDE", "Vornamen Schweiz/Deutschland (eigene Liste)", vornamen),
        ("surnamesCHDE", "Nachnamen Schweiz/Deutschland (eigene Liste)", nachnamen),
    ])
    groessen["ListeOrte.swift"] = schreibe_swift("ListeOrte.swift", [
        ("placesCH", "Schweizer Orte, Kantone, Vereine, Berge, Seen; dazu DE/AT-Städte (eigene Liste)", orte),
    ])
    groessen["ListePassphrase.swift"] = schreibe_swift("ListePassphrase.swift", [
        ("passphraseWords", "Passphrasen-Wörter: genau 2048, 4–8 Buchstaben a–z", passphrase),
    ])

    print("| Liste | Zeilen |")
    print("|---|---|")
    for name, n in [("zxcvbn passwords", len(z["passwords"])), ("passwoerter_de", len(passwoerter_de)),
                    ("zxcvbn english_wikipedia", len(z["english_wikipedia"])),
                    ("zxcvbn us_tv_and_film", len(z["us_tv_and_film"])),
                    ("web2 (Zusatz)", len(web2_zeilen)), ("woerter_de", len(woerter_de)),
                    ("zxcvbn surnames", len(z["surnames"])), ("zxcvbn male_names", len(z["male_names"])),
                    ("zxcvbn female_names", len(z["female_names"])), ("vornamen_ch_de", len(vornamen)),
                    ("nachnamen_ch_de", len(nachnamen)), ("orte_vereine_ch", len(orte)),
                    ("passphrase_de", len(passphrase))]:
        print("| %s | %d |" % (name, n))
    print()
    gesamt = 0
    for datei, groesse in sorted(groessen.items()):
        gesamt += groesse
        print("%-28s %9d Byte" % (datei, groesse))
    print("%-28s %9d Byte" % ("gesamt", gesamt))


if __name__ == "__main__":
    main()
