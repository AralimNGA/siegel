#!/usr/bin/env python3
"""Fester Korpus für den Bit-Gleichheits-Test der Stärke-Schätzung Swift ↔ C# (SPEC-WINDOWS W7).

Erzeugt deterministisch (feste Saat) in windows/tests/Siegel.Core.Tests/Werkzeuge/Daten/:
- staerke_korpus.txt.gz   ≥ 10 000 Fälle: je Zeile Base64(Passwort) und Base64(Benutzereingabe)…, Tab-getrennt
  (Zufall, Passphrasen, typische Muster, Daten, Tastaturfolgen, Namen + Jahr, l33t, Vorlagen, Unicode mit NBSP,
  Kombinationszeichen, Emoji, Indisch, Hangul, Steuerzeichen, sehr lange Eingaben, Benutzereingaben)
- staerke_erwartet.txt.gz die Werte der Swift-Referenz (SiegelStaerkeExport bewerten, Bezugsjahr 2026):
  bits (17 signifikante Stellen) \\t Stufe \\t Zeichenzahl \\t Regel erfüllt
- graphem_korpus.txt.gz / graphem_erwartet.txt.gz: 20 000 Zufallsfolgen aus allen Graphem-Klassen und Swifts
  Character-Grenzen dazu (prüft die eigene UAX-#29-Zerlegung in C#)
- autofill_korpus.txt.gz / autofill_erwartet.txt.gz (12 000 Paare) und titel_korpus.txt.gz / titel_erwartet.txt.gz
  (6 000 Adressen): Gegenprobe für AutofillMatcher und den CSV-Titel aus der URL (Foundation-Verhalten)
- nfc_korpus.txt.gz / nfc_erwartet.txt.gz: Normalisierung wie Foundation (`precomposedStringWithCanonicalMapping`)
  und `PasswordNormalizer.normalize` (SPEC §1.1) – jedes Zeichen der Tabelle swift_nfc.txt.gz einzeln und mit
  Kombinationszeichen, jedes Paar (auch blockiert), Hangul-Grenzfälle, alle Unicode-16-Zerlegungen, U+FFFE, Zufall
  (Befunde krypto-1/krypto-2)
- gleich_korpus.txt.gz / gleich_erwartet.txt.gz: Paare und ob Swift-`String` sie für gleich hält (Befund krypto-4)

Aufruf: python3 windows/skripte/korpus_erzeugen.py [--ohne-swift] [--pruefen]
Voraussetzung: windows/skripte/listen_exportieren.py ist gelaufen (Listen und Unicode-Tabelle). Kein Netz.
Der Korpus ist erfundenes Testmaterial (keine echten Passwörter).
"""

from __future__ import annotations

import argparse
import base64
import gzip
import os
import random
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

PAKET = Path(__file__).resolve().parents[2]
LISTEN = PAKET / "windows/src/Siegel.Werkzeuge/Staerke/Listen"
UNICODE = PAKET / "windows/src/Siegel.Werkzeuge/Unicode/swift_unicode.txt.gz"
NFC_TABELLE = PAKET / "windows/src/Siegel.Werkzeuge/Unicode/swift_nfc.txt.gz"
DATEN = PAKET / "windows/tests/Siegel.Core.Tests/Werkzeuge/Daten"
JAHR = 2026
SAAT = 20261018


def liste(name: str) -> list[str]:
    text = gzip.decompress((LISTEN / f"{name}.txt.gz").read_bytes()).decode("utf-8")
    return [zeile.split("\t")[0] for zeile in text.split("\n") if zeile]


def gz(daten: bytes) -> bytes:
    return gzip.compress(daten, compresslevel=9, mtime=0)


class Korpus:
    def __init__(self) -> None:
        self.r = random.Random(SAAT)
        self.faelle: list[tuple[str, list[str]]] = []
        self.gesehen: set[tuple[str, tuple[str, ...]]] = set()
        self.passphrase = liste("passphraseWords")
        self.deutsch = liste("germanWords")[:3000]
        self.englisch = liste("englishWikipedia")[:5000]
        self.passwoerter = liste("passwords")[:5000]
        self.passwoerter_de = liste("passwordsGerman")
        self.vornamen = liste("firstNamesCHDE") + liste("maleNames")[:400] + liste("femaleNames")[:400]
        self.nachnamen = liste("surnamesCHDE") + liste("surnames")[:600]
        self.orte = liste("placesCH")
        self.web2 = []

    def add(self, passwort: str, eingaben: list[str] | None = None) -> None:
        eingaben = eingaben or []
        schluessel = (passwort, tuple(eingaben))
        if schluessel in self.gesehen:
            return
        self.gesehen.add(schluessel)
        self.faelle.append((passwort, eingaben))

    # Bausteine

    def wort(self) -> str:
        quelle = self.r.choice([self.deutsch, self.englisch, self.passwoerter, self.passwoerter_de, self.vornamen,
                                self.nachnamen, self.orte, self.passphrase])
        return self.r.choice(quelle)

    def schreibweise(self, w: str) -> str:
        art = self.r.random()
        if art < 0.35:
            return w
        if art < 0.7:
            return w[:1].upper() + w[1:]
        if art < 0.82:
            return w.upper()
        return "".join(c.upper() if self.r.random() < 0.5 else c for c in w)

    def l33t(self, w: str, rate: float = 0.5) -> str:
        tabelle = {"a": "4@", "e": "3", "i": "1!|", "l": "1|!", "o": "0", "s": "5$", "t": "7", "g": "9"}
        return "".join(self.r.choice(tabelle[c]) if c in tabelle and self.r.random() < rate else c for c in w)

    def zahl(self) -> str:
        art = self.r.random()
        if art < 0.4:
            return str(self.r.randint(1900, 2030))
        if art < 0.6:
            return str(self.r.randint(0, 99)).zfill(self.r.choice([1, 2]))
        if art < 0.8:
            return "".join(str(i % 10) for i in range(1, self.r.randint(2, 8)))
        return str(self.r.randint(0, 999999))

    def symbole(self) -> str:
        return "".join(self.r.choice("!?.#*$%&+-_@") for _ in range(self.r.randint(0, 3)))

    # Kategorien

    def zufall(self) -> None:
        druckbar = [chr(c) for c in range(33, 127)]
        for _ in range(1200):
            self.add("".join(self.r.choice(druckbar) for _ in range(self.r.randint(1, 40))))
        for alphabet, anzahl in (("0123456789", 300), ("abcdefghijklmnopqrstuvwxyz", 300), ("0123456789abcdef", 200),
                                 ("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 200), ("abc", 100), ("01", 100)):
            for _ in range(anzahl):
                self.add("".join(self.r.choice(alphabet) for _ in range(self.r.randint(1, 24))))
        mit_leer = [chr(c) for c in range(32, 127)]
        for _ in range(200):
            self.add("".join(self.r.choice(mit_leer) for _ in range(self.r.randint(8, 30))))

    def passphrasen(self) -> None:
        trenner = ["-", " ", "_", ".", ",", ", ", " - ", "--", "", "1", "/", "+", "|", "~", ";", ":", "  ", "#", "*",
                   "!", "?", "\u00a0", ". ", "-_"]
        for _ in range(1500):
            k = self.r.randint(2, 8)
            woerter = [self.r.choice(self.passphrase) for _ in range(k)]
            if self.r.random() < 0.2:
                woerter = [self.l33t(w, 0.3) for w in woerter]
            art = self.r.random()
            if art < 0.15:
                woerter = [w.capitalize() for w in woerter]
            elif art < 0.22:
                woerter = [w.upper() for w in woerter]
            elif art < 0.3:
                woerter = [self.schreibweise(w) for w in woerter]
            if self.r.random() < 0.75:
                t = self.r.choice(trenner)
                text = t.join(woerter)
            else:
                text = woerter[0]
                for w in woerter[1:]:
                    text += self.r.choice(trenner + [str(self.r.randint(0, 99))]) + w
            if self.r.random() < 0.2:
                text += self.zahl() + self.symbole()
            self.add(text)

    def muster(self) -> None:
        for _ in range(1500):
            art = self.r.random()
            w = self.schreibweise(self.wort())
            if art < 0.4:
                self.add(w + self.zahl() + self.symbole())
            elif art < 0.55:
                self.add(self.zahl() + w + self.symbole())
            elif art < 0.7:
                self.add(w + self.r.choice(["_", ".", "-", "", "&", " "]) + self.schreibweise(self.wort()) + self.zahl())
            elif art < 0.8:
                self.add(self.r.choice(self.passwoerter))
            elif art < 0.9:
                self.add(self.r.choice(self.passwoerter_de) + self.symbole())
            else:
                self.add(w + w[::-1] + self.symbole())

    def daten(self) -> None:
        for _ in range(600):
            j = self.r.randint(1000, 2099) if self.r.random() < 0.1 else self.r.randint(1940, 2030)
            m = self.r.randint(1, 12)
            t = self.r.randint(1, 31)
            jj = j % 100
            form = self.r.choice([
                f"{t:02d}.{m:02d}.{j}", f"{t}.{m}.{jj:02d}", f"{j}-{m:02d}-{t:02d}", f"{t:02d}{m:02d}{jj:02d}",
                f"{t:02d}{m:02d}{j}", f"{j}{m:02d}{t:02d}", f"{m:02d}/{t:02d}/{j}", f"{t}/{m}/{j}", f"{t} {m} {j}",
                f"{t}_{m}_{jj}", f"{t}\\{m}\\{j}", f"{t:02d}.{m:02d}.{jj:02d}", f"{j}", f"{t}{m}{j}",
                f"{t:02d}-{m:02d}-{j}", f"{t}.{m}-{j}",
            ])
            vorne = self.schreibweise(self.wort()) if self.r.random() < 0.4 else ""
            hinten = self.symbole() if self.r.random() < 0.4 else ""
            self.add(vorne + form + hinten)

    def tastatur(self) -> None:
        reihen = ["§1234567890'^", "qwertzuiopü¨", "asdfghjklöä$", "<yxcvbnm,.-", "°+\"*ç%&/()=?`",
                  "QWERTZUIOPÈ!", "ASDFGHJKLÉÀ£", ">YXCVBNM;:_", "`1234567890-=", "qwertyuiop[]\\",
                  "asdfghjkl;'", "zxcvbnm,./", "~!@#$%^&*()_+", "QWERTYUIOP{}|", "ASDFGHJKL:\"", "ZXCVBNM<>?",
                  "789", "456", "123", "/*-", "147", "258", "369", "7410", "8520", "9630", "+-*/"]
        diagonal = ["1qay2wsx3edc", "1qaz2wsx3edc", "zaq12wsx", "!QAY\"WSX", "qayxsw", "rfvtgb", "ujmnhz", "7412369",
                    "147258369", "963852741", "159753", "741852963", "asdf;lkj", "qweasdzxc"]
        for _ in range(600):
            art = self.r.random()
            if art < 0.6:
                reihe = self.r.choice(reihen)
                a = self.r.randint(0, max(0, len(reihe) - 3))
                b = self.r.randint(a + 3, len(reihe)) if len(reihe) >= 3 else len(reihe)
                stueck = reihe[a:b]
                if self.r.random() < 0.3:
                    stueck = stueck[::-1]
            else:
                stueck = self.r.choice(diagonal)
                if self.r.random() < 0.3:
                    stueck = stueck[: self.r.randint(3, len(stueck))]
            if self.r.random() < 0.3:
                stueck = self.schreibweise(stueck)
            if self.r.random() < 0.3:
                stueck += self.zahl()
            if self.r.random() < 0.2:
                stueck = stueck + stueck
            self.add(stueck)

    def wiederholungen(self) -> None:
        for _ in range(500):
            art = self.r.random()
            if art < 0.25:
                self.add(self.r.choice("aA1!xZ.ä-") * self.r.randint(2, 30))
            elif art < 0.5:
                einheit = self.r.choice(["ab", "abc", "123", "1a", "a1b2", "hund", "Hund1", "xy!", "äö", "qwe"])
                self.add(einheit * self.r.randint(2, 8) + self.r.choice(["", "!", "1", einheit[:1]]))
            elif art < 0.8:
                start = self.r.choice([ord("a"), ord("A"), ord("0"), 0x3B1, 0x430, ord("m"), 0x5D0])
                schritt = self.r.choice([1, 1, 2, 3, 4, 5, -1, -2, 6])
                laenge = self.r.randint(3, 12)
                zeichen = []
                for i in range(laenge):
                    c = start + i * schritt
                    if 0 < c < 0xD800:
                        zeichen.append(chr(c))
                self.add("".join(zeichen) + self.symbole())
            else:
                w = self.wort()
                self.add((w + self.r.choice(["", "1", "!", " "])) * self.r.randint(2, 4))

    def namen(self) -> None:
        for _ in range(600):
            v = self.r.choice(self.vornamen)
            n = self.r.choice(self.nachnamen)
            j = str(self.r.randint(1940, 2026))
            form = self.r.choice([v.capitalize() + j, v + "." + n + j, v.capitalize() + n.capitalize() + j[-2:],
                                  n.upper() + j, v.capitalize() + j + "!", j + v, v + "_" + n, v.capitalize() + "&"
                                  + self.r.choice(self.vornamen).capitalize() + j])
            self.add(form)

    def l33t_faelle(self) -> None:
        for _ in range(500):
            w = self.r.choice(self.passwoerter + self.deutsch + self.englisch)
            self.add(self.schreibweise(self.l33t(w, self.r.choice([0.3, 0.6, 1.0]))) + self.symbole())

    def vorlagen(self) -> None:
        tage = [["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"], ["Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag",
                "Samstag", "Sonntag"], ["mon", "tue", "wed", "thu", "fri", "sat", "sun"], ["Lu", "Ma", "Me", "Je",
                "Ve", "Sa", "Di"], ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"],
                ["lunedì", "martedì", "mercoledì", "giovedì", "venerdì", "sabato", "domenica"],
                ["Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"],
                ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
                 "november", "december"], ["janv", "févr", "mars", "avr", "mai", "juin", "juil", "août", "sept", "oct",
                "nov", "déc"], ["gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno"],
                ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli"]]
        orte = [("Thun", 3600), ("Bern", 3000), ("Biel", 2500), ("Basel", 4000), ("Zürich", 8000), ("Luzern", 6000),
                ("Zug", 6300), ("Chur", 7000), ("Spiez", 3700), ("Aarau", 5000), ("Kerze", 3600), ("Uster", 8610)]
        for _ in range(500):
            art = self.r.random()
            if art < 0.4:
                w = self.schreibweise(self.r.choice(self.deutsch + self.vornamen))
                start = self.r.randint(0, 20)
                schritt = self.r.choice([1, 2, 5, 10, -1, 3, 1])
                n = self.r.randint(2, 7)
                breite = self.r.choice([0, 0, 2])
                teile = []
                for i in range(n):
                    zahl = max(0, start + i * schritt)
                    z = str(zahl).zfill(breite) if breite else str(zahl)
                    teile.append(w + z if self.r.random() < 0.85 else z + w)
                sep = self.r.choice(["", "", "-", ".", " "])
                text = sep.join(teile)
                if self.r.random() < 0.2:
                    text += w[: self.r.randint(1, len(w))]
                self.add(text)
            elif art < 0.75:
                reihe = self.r.choice(tage)
                s = self.r.randint(0, len(reihe) - 1)
                richtung = self.r.choice([1, 1, -1])
                n = self.r.randint(2, len(reihe))
                sep = self.r.choice(["", "-", ".", " ", "/", ", ", "--", "1"])
                teile = [reihe[(s + richtung * i) % len(reihe)] for i in range(n)]
                if self.r.random() < 0.3:
                    teile = [t.upper() for t in teile]
                self.add(sep.join(teile) + (self.symbole() if self.r.random() < 0.3 else ""))
            else:
                n = self.r.randint(1, 4)
                sep = self.r.choice(["", " ", "-", "."])
                innen = self.r.choice(["", " ", "-"])
                vorne = self.r.random() < 0.6
                teile = []
                for _ in range(n):
                    ort, plz = self.r.choice(orte)
                    if self.r.random() < 0.3:
                        plz += self.r.randint(1, 99)
                    teile.append(f"{ort}{innen}{plz}" if vorne else f"{plz}{innen}{ort}")
                self.add(sep.join(teile))

    def saetze(self) -> None:
        for _ in range(400):
            n = self.r.randint(3, 10)
            woerter = [self.r.choice(self.deutsch[:1500] if self.r.random() < 0.6 else self.englisch[:2000])
                       for _ in range(n)]
            woerter = [w.capitalize() if self.r.random() < 0.3 else w for w in woerter]
            if self.r.random() < 0.3:
                woerter.insert(self.r.randint(0, len(woerter)), str(self.r.randint(1, 2030)))
            sep = self.r.choice([" ", " ", "", "-", "_", ", ", "  "])
            self.add(sep.join(woerter) + self.r.choice(["", ".", "!", "?", "!!"]))

    def unicode_faelle(self) -> None:
        bausteine = [
            "ä", "ö", "ü", "Ä", "Ö", "Ü", "ß", "ẞ", "é", "è", "à", "ç", "ñ", "ø", "å", "æ", "œ", "ł",
            "a\u0308", "o\u0308", "u\u0308", "e\u0301", "A\u030a", "q\u0307", "x\u0323\u0302", "i\u0307",
            "\u00a0", "\u2003", "\u202f", "\u3000", "\u2009", "\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad",
            "İ", "ı", "Σ", "σ", "ς", "Ω", "ά", "ΐ", "ǅ", "ǈ", "ﬀ", "ﬁ", "Ⅳ", "ⅻ", "ⓐ", "Ⓐ", "Ａ", "ｚ", "１",
            "𝐀", "𝔞", "𐐀", "𐐨", "½", "²", "٣", "一", "二", "三", "十", "百", "龍", "虎", "あ", "ア", "カ\u3099",
            "한", "글", "각", "ᄀ", "ᅡ", "ᆨ", "ㄱ",
            "क\u094dष", "नमस\u094dत\u0947", "क\u094d\u200dष", "स\u094dत\u094dर", "ক\u09cdষ", "ন\u09cdদ", "த\u0bcd", "ಕ\u0ccdಷ",
            "😀", "👍🏽", "👨\u200d👩\u200d👧", "🏳\ufe0f\u200d🌈", "🇨🇭", "🇩🇪", "🇨", "#\ufe0f\u20e3", "1\ufe0f\u20e3", "❤\ufe0f", "☺", "©", "™", "🏴\U000e0067\U000e0062\U000e0073\U000e0063\U000e0074\U000e007f",
            "Ж", "ж", "Привет", "мир", "Ελλάδα", "שלום", "مرحبا", "مرحبا", "ไทย", "ภาษา",
            "\t", "\n", "\r\n", "\r", "\u0000", "\u0007", "\u007f", "\u0085", "\u2028", "\u202e", "\u2066",
            "€", "£", "¥", "§", "°", "±", "×", "÷", "µ", "¶", "¿", "¡", "«", "»", "„", "“", "”", "‚", "‘", "’",
            "\u0600", "\ufffe", "\uffff", "a\ufffee\u0301", "ः", "ำ", "\ufe0f", "\U0001f3fb", "\U000e0001", "\U0010fffd", "\ue000", "\u0378",
        ]
        for _ in range(1500):
            art = self.r.random()
            if art < 0.35:
                text = "".join(self.r.choice(bausteine) for _ in range(self.r.randint(1, 12)))
            elif art < 0.6:
                w = self.schreibweise(self.wort())
                text = w + self.r.choice(bausteine) + self.zahl() + self.r.choice(["", self.r.choice(bausteine)])
            elif art < 0.8:
                woerter = [self.r.choice(self.passphrase) for _ in range(self.r.randint(3, 7))]
                text = self.r.choice(["\u00a0", "\u2003", "\u202f", "\u3000", " ", "\u2009"]).join(woerter)
                if self.r.random() < 0.3:
                    text = unicodedata.normalize("NFD", text.replace("a", "ä").replace("u", "ü"))
            else:
                w = self.r.choice(self.deutsch + self.vornamen + self.nachnamen + self.orte)
                if self.r.random() < 0.5:
                    w = unicodedata.normalize("NFD", w)
                text = self.schreibweise(w) + self.r.choice(["", "\u00a0", "\u0301", "\u200d"]) + self.zahl()
            self.add(text)

    def lang(self) -> None:
        druckbar = [chr(c) for c in range(33, 127)]
        for _ in range(60):
            self.add("".join(self.r.choice(druckbar) for _ in range(self.r.randint(257, 2000))))
        for _ in range(60):
            periode = self.r.randint(1, 300)
            einheit = "".join(self.r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(periode))
            laenge = self.r.randint(257, 1500)
            text = (einheit * (laenge // periode + 2))[:laenge]
            if self.r.random() < 0.5:
                text += self.r.choice(["", "!!", "xyz", "Ende2026", "1"])
            self.add(text)
        for _ in range(40):
            satz = " ".join(self.r.choice(self.deutsch[:1500]) for _ in range(self.r.randint(15, 40)))
            self.add((satz + self.r.choice([" ", ". ", ""])) * self.r.randint(2, 3) + self.r.choice(["", "!", "!!"]))
        for _ in range(20):
            self.add("-".join(self.r.choice(self.passphrase) for _ in range(self.r.randint(40, 80))))
        for _ in range(20):
            einheit = "".join(self.r.choice(["ä", "e\u0301", "😀", "क\u094dष", "한", "\u00a0", "a", "1"])
                              for _ in range(self.r.randint(1, 40)))
            self.add(einheit * self.r.randint(8, 60))
        self.add("a" * 5000)
        self.add("ab" * 2000)
        self.add("".join(self.r.choice(druckbar) for _ in range(4800)))

    def benutzereingaben(self) -> None:
        konten = [["siegel", "aralim"], ["siegel", "jmueller", "jürg müller-zbinden", "jürg", "juerg", "jurg",
                  "müller", "mueller", "muller", "zbinden"], ["siegel", "anna"], ["siegel", "zwurbelmann"],
                  ["Siegel", "Aralim Ößtürk", "İnan"], ["siegel", "", "x"], ["siegel", "levin", "levin2008"]]
        for _ in range(400):
            eingaben = self.r.choice(konten)
            basis = self.r.choice([e for e in eingaben if e] or ["siegel"])
            text = self.schreibweise(basis) + self.zahl() + self.symbole()
            if self.r.random() < 0.3:
                text = self.wort() + text
            if self.r.random() < 0.2:
                text = self.l33t(text, 0.5)
            self.add(text, eingaben)

    def grenzfaelle(self) -> None:
        for text in ["", " ", "  ", "\u00a0", "\t", "\n", "\r\n", "a", "A", "1", "!", "ä", "😀", "\u0301",
                     "\u0000", "e\u0301", "\u200d", "aaaaaaaaaaaaa", "Aaaaaaaaaaaa1!", "Passwort1234!",
                     "Passwort2026!", "Sommer2026!!!", "Qwertz123456!", "YB-Meister-2026", "kV7#pQ2$mZ9!xR4@tL8&",
                     "龍虎鳳凰麒麟亀蛇", "correcthorsebatterystaple", "Tr0ub4dor&3", "P@ssw0rt", "trowssap",
                     "|1eb3", "s0mm3r", "1qay2wsx", "ztrewq", "24.12.1990", "241290", "1990-12-24", "1.1.91",
                     "Hund1Hund2Hund3Hund4Hund5Hund6", "Mo-Di-Mi-Do-Fr-Sa-So", "Thun3600Bern3000Biel2500",
                     "Mein Hund heisst Bello", "Ich wohne seit 2015 in Biel", "kerze-vulkan-flaute-pirat",
                     "Der rote Fuchs springt über den faulen Hund", "a\ufffeb", "\ufffe", "e\u0301\ufffe\u0301", "ab\u00a0cd ef", "cafe\u0301"]:
            self.add(text)
        self.add("Aralim2008!!!", ["aralim"])
        self.add("Zwurbelmann1999", ["zwurbelmann"])
        self.add("JuergMueller1971!", ["siegel"])
        self.add("Siegel2026Siegel!", ["siegel"])

    def bauen(self) -> list[tuple[str, list[str]]]:
        self.grenzfaelle()
        self.zufall()
        self.passphrasen()
        self.muster()
        self.daten()
        self.tastatur()
        self.wiederholungen()
        self.namen()
        self.l33t_faelle()
        self.vorlagen()
        self.saetze()
        self.unicode_faelle()
        self.lang()
        self.benutzereingaben()
        return self.faelle


def graphem_korpus() -> list[str]:
    """Zufallsfolgen aus allen Graphem-Klassen (aus der Swift-Tabelle), dazu ASCII und bekannte Sequenzen."""
    r = random.Random(SAAT + 1)
    gruppen: dict[tuple[str, str, str], list[int]] = {}
    for zeile in gzip.decompress(UNICODE.read_bytes()).decode("utf-8").split("\n"):
        if not zeile.startswith("R "):
            continue
        teile = zeile.split()
        von, bis = int(teile[1], 16), int(teile[2], 16)
        schluessel = (teile[5], teile[6], teile[7])          # Klasse, Bildzeichen, InCB
        liste_ = gruppen.setdefault(schluessel, [])
        for _ in range(min(40, bis - von + 1)):
            liste_.append(r.randint(von, bis))
    gruppen_liste = sorted(gruppen.items())
    extra = [0x0915, 0x094D, 0x0937, 0x200D, 0x1F600, 0x1F3FD, 0x1F1E8, 0x1F1ED, 0x0D, 0x0A, 0x1100, 0x1161, 0x11A8,
             0xAC00, 0xAC01, 0x0600, 0x0903, 0x0308, 0xFE0F, 0x20E3, 0x0E33, 0x0061, 0x0020, 0x00A0]
    faelle = []
    for _ in range(20000):
        laenge = r.randint(1, 12)
        skalare = []
        for _ in range(laenge):
            if r.random() < 0.45:
                skalare.append(r.choice(extra))
            else:
                skalare.append(r.choice(r.choice(gruppen_liste)[1]))
        faelle.append("".join(chr(s) for s in skalare))
    return faelle


def nfc_tabelle() -> dict[str, dict]:
    """Die von Swift gemessene Tabelle (D/O/SD Zerlegung, C Klasse, P Paare)."""
    daten: dict[str, dict] = {"D": {}, "O": {}, "SD": {}, "C": {}, "P": {}, "K": {}}
    for zeile in gzip.decompress(NFC_TABELLE.read_bytes()).decode("utf-8").split("\n"):
        if not zeile or zeile.startswith("#"):
            continue
        t = zeile.split()
        if t[0] in ("D", "O", "SD"):
            daten[t[0]][int(t[1], 16)] = [int(x, 16) for x in t[2:]]
        elif t[0] in ("C", "K"):
            daten[t[0]][int(t[1], 16)] = int(t[2])
        elif t[0] == "P":
            daten["P"][(int(t[1], 16), int(t[2], 16))] = int(t[3], 16)
    return daten


# Kombinationszeichen verschiedener Klassen (1, 7, 9, 129, 202, 216, 218, 220, 222, 226, 228, 230, 232, 233, 240)
MARKEN = [0x0334, 0x093C, 0x094D, 0x0F71, 0x0327, 0x031B, 0x302A, 0x0323, 0x059A, 0x1D16D, 0x05AE, 0x0301, 0x0315,
          0x035C, 0x0345, 0x0308, 0x0300, 0x0316]
BESONDERE = [0xFFFE, 0xFFFF, 0xFDD0, 0xFDEF, 0x1FFFE, 0x10FFFF, 0x0378, 0xE0080, 0x2FFFF, 0xE000, 0x10FFFD, 0xFFFD,
             0x00A0, 0x2003, 0x3000, 0x0020, 0x200B, 0xFEFF, 0x0000, 0x0009, 0x16D67, 0x16D68, 0x105D2, 0x105C9,
             0x1611E, 0x16121, 0x113C2, 0x113C5, 0x1ACF, 0x1E6E3]
HANGUL_L = [0x10FF, 0x1100, 0x1101, 0x1112, 0x1113, 0x1114, 0x115F, 0xA960, 0xA97C]
HANGUL_V = [0x1160, 0x1161, 0x1162, 0x1175, 0x1176, 0x1177, 0x11A2, 0xD7B0]
HANGUL_T = [None, 0x11A6, 0x11A7, 0x11A8, 0x11C2, 0x11C3, 0x11C4, 0x11FF, 0xD7CB]


def nfc_korpus() -> list[str]:
    """Zeichenketten für die Normalisierung Swift ↔ C#: Tabelle vollständig, Paare, Blockieren, Hangul, Zufall."""
    r = random.Random(SAAT + 3)
    daten = nfc_tabelle()
    faelle: list[str] = []
    gesehen: set[str] = set()

    def add(*skalare: int | None) -> None:
        text = "".join(chr(s) for s in skalare if s is not None)
        if text and text not in gesehen:
            gesehen.add(text)
            faelle.append(text)

    zerlegbar = sorted(set(daten["D"]) | set(daten["O"]) | set(daten["SD"]))
    for s in zerlegbar:
        add(s)
        add(*daten["D"].get(s, daten["O"].get(s, daten["SD"].get(s, [s]))))
        for m in (0x0334, 0x0345, 0x0301, 0x0323):
            add(s, m)
        add(0x61, s, 0x0301)
    for s in sorted(daten["C"]):
        add(s)
        add(0x61, s)
        add(0x61, s, 0x0334)
        add(0x61, 0x0345, s)
        add(0x61, s, 0x0301)
        add(0x61, 0x0301, s)
    for (a, b), c in sorted(daten["P"].items()):
        add(a, b)
        add(c)
        add(b, a)
        add(a, b, b)
        add(0x61, a, b)
        add(a, b, 0x0301)
        for m in r.sample(MARKEN, 3):
            add(a, m, b)
        add(a, 0x61, b)
        add(a, 0xFFFE, b)
    # Foundation-Eigenheiten (gemessen): Verdoppler nach Nicht-Starter am Anfang bzw. nach Einzelzerlegung, träge Zeichen
    verdoppler = sorted(a for (a, b) in daten["P"] if a == b)
    zweite_zu: dict[int, list[int]] = {}
    erste_zu: dict[int, list[int]] = {}
    for (a, b) in sorted(daten["P"]):
        zweite_zu.setdefault(a, []).append(b)
        erste_zu.setdefault(b, []).append(a)
    einzeln = sorted(s for s, z in daten["D"].items() if len(z) == 1)
    for x in verdoppler:
        for s in einzeln:
            add(s, x)
            add(0x61, s, x)
            add(s, x, x)
            add(s, 0x0301, x)
        for m in sorted(daten["C"]):
            add(m, x)
            add(0x61, m, x)
            add(m, m, x)
        for z in zweite_zu.get(x, []):
            add(0x0301, x, z)
            add(0xF928, x, z)
    for s in sorted(daten["O"]):
        for q in zweite_zu.get(s, []) + [0x0301, 0x0334]:
            add(s, q)
        for e in erste_zu.get(daten["O"][s][0], []):
            add(e, s)
            add(e, *daten["O"][s])
    # Foundation sucht Paare mit einem zweiten Glied aus der BMP über die unteren 16 Bit des Starters (gemessen)
    for (a, b) in sorted(daten["P"]):
        if a <= 0xFFFF and b <= 0xFFFF:
            for ebene in (0x10000, 0xE0000, 0xF0000):
                add(ebene + a, b)
                add(0x61, ebene + a, b)
    for s in sorted(daten["K"]):
        add(0x61, s, 0x0334)
        add(0x61, 0x0334, s)
    for tib in (0x0F73, 0x0F75, 0x0F81):
        for m in MARKEN:
            add(0x61, m, tib)
            add(0x61, tib, m)
            add(0x61, m, tib, m)
    for s in BESONDERE:
        add(s)
        add(0x61, s, 0x0301)
        add(s, 0x0301)
        add(0x65, 0x0301, s, 0x65, 0x0301)
    for l in HANGUL_L:
        for v in HANGUL_V:
            for t_ in HANGUL_T:
                add(l, v, t_)
                add(l, 0x0334, v, t_)
                add(l, v, 0x0301, t_)
                add(l, v, t_, t_)
    for silbe in (0xAC00, 0xAC01, 0xAC1C, 0xD788, 0xD7A3):
        for t_ in HANGUL_T + [0x1161, 0x1100, 0x0301]:
            add(silbe, t_)
            add(0x1100, silbe, t_)
    # alle kanonischen Zerlegungen der Norm, die dieses Python kennt (Unicode 16: auch Kirat Rai, Todhri, Tulu-Tigalari)
    for s in range(0x110000):
        if 0xD800 <= s <= 0xDFFF:
            continue
        d = unicodedata.decomposition(chr(s))
        if d and not d.startswith("<") and not 0xAC00 <= s <= 0xD7A3:
            teile = [int(x, 16) for x in d.split()]
            if s >= 0x10000 or r.random() < 0.3:
                add(*teile)
                add(*[ord(c) for c in unicodedata.normalize("NFD", chr(s))])
    # Zufall aus allem Obigen, ASCII und Hangul-Jamo
    vorrat = (zerlegbar + sorted(daten["C"]) + [b for (_, b) in daten["P"]] + [a for (a, _) in daten["P"]]
              + BESONDERE + MARKEN + HANGUL_L + [v for v in HANGUL_V] + [t_ for t_ in HANGUL_T if t_] + [0xAC00, 0xAC01])
    ascii_ = [ord(c) for c in "aAeEoOuUiIsSnNcCzZ 0123456789!#-_"]
    for _ in range(20000):
        add(*[r.choice(vorrat) if r.random() < 0.7 else r.choice(ascii_) for _ in range(r.randint(1, 10))])
    return faelle


def gleich_korpus(nfc_faelle: list[str]) -> list[tuple[str, str]]:
    """Paare für die Gleichheit von Swift-String: kanonisch gleiche Formen (Norm), Umordnungen, Hangul, Ungleiches."""
    r = random.Random(SAAT + 4)
    paare: list[tuple[str, str]] = []
    gesehen: set[tuple[str, str]] = set()

    def add(a: str, b: str) -> None:
        if (a, b) not in gesehen:
            gesehen.add((a, b))
            paare.append((a, b))

    for text in nfc_faelle:
        if r.random() < 0.45:
            nfd = unicodedata.normalize("NFD", text)
            add(text, nfd)
            add(text, unicodedata.normalize("NFC", text))
            skalare = list(nfd)
            if len(skalare) >= 3:
                i = r.randrange(1, len(skalare) - 1)
                skalare[i], skalare[i + 1] = skalare[i + 1], skalare[i]
                add(text, "".join(skalare))
            if r.random() < 0.1:
                add(text, text + "x")
    for a, b in [("\uac00\u11a8", "\uac01"), ("\u1100\u1161\u11a7", "\uac00"), ("\u1100\u1176", "\uae4c"),
                 ("\U00016d67\U00016d67", "\U00016d68"), ("\U000105d2\u0307", "\U000105c9"),
                 ("\U0001611e\U0001611e", "\U00016121"), ("Cafe\u0301", "Caf\u00e9"), ("a\u00a0b", "a b"),
                 ("abc\ufffedef", "abc\ufffedef"), ("a\u0301\u0323", "a\u0323\u0301"), ("\u212b", "\u00c5")]:
        add(a, b)
    return paare


URL_HOSTS = [
    "example.com", "login.example.com", "www.example.com", "a.b.example.com", "EXAMPLE.com.", "bücher.de",
    "xn--bcher-kva.de", "www.bücher.de", "straße.de", "xn--strae-oqa.de", "münchen.de", "例え.jp", "xn--r8jz45g.jp",
    "аррӏе.com", "xn--80ak6aa92e.com", "apple.com", "pаypal.com", "paypal.com", "gοοgle.com", "ｅｘａｍｐｌｅ.com",
    "192.168.1.1", "10.192.168.1.1", "1.1", "evil.1.1", "[fd00::1]", "[fd00::2]", "[::1]", "localhost",
    "evil.localhost", "ch", "bank.ch", "admin.ch", "co.uk", "bank.co.uk", "secure.bank.co.uk", "evil.co.uk", "github.io",
    "alice.github.io", "docs.alice.github.io", "bob.github.io", "beispiel-bank.example", "beispiel-bank.example.evil.com",
    "xn--beispiel-bnk-ndb.example", "ex_ample.com", "ÄÖÜ.ch", "Bücher.DE", "0x7f.1", "1.2.3", "a..b.com",
    ".example.com", "x-.com", "-x.com", "ab--cd.com", "velo.example.ch", "nas.example.ch", "sbb.ch", "www.sbb.ch",
]
URL_SCHEMES = ["https://", "http://", "", "ftp://", "HTTPS://", "android://"]
URL_PORTS = ["", ":443", ":80", ":8443", ":5001", ":0", ":70000", ":", ":080"]
URL_PFADE = ["", "/", "/login", "/x?y=1", "?q=1", "#frag", "/a b", "/ä"]
URL_BENUTZER = ["", "user:pw@", "a@", "bank.ch@"]


def url_korpus() -> tuple[list[tuple[str, str]], list[str]]:
    """Adressen für AutofillMatcher und den CSV-Titel (Gegenprobe mit Swift/Foundation): typische, internationale und
    Phishing-Formen, dazu Zufall aus einem kleinen Alphabet wie im Swift-Test."""
    r = random.Random(SAAT + 2)

    def url() -> str:
        if r.random() < 0.25:
            alphabet = list("abc.-:/@\\?#%[]1 äаxn-0")
            return ("https://" if r.random() < 0.5 else "") + "".join(r.choice(alphabet) for _ in range(r.randint(0, 20)))
        return r.choice(URL_SCHEMES) + r.choice(URL_BENUTZER) + r.choice(URL_HOSTS) + r.choice(URL_PORTS) + r.choice(URL_PFADE)

    paare = []
    for _ in range(12000):
        eintrag = url()
        dienst = url() if r.random() < 0.7 else r.choice(["", "www.", "login.", "evil."]) + eintrag.split("://")[-1]
        paare.append((eintrag, dienst))
    titel = [url() for _ in range(6000)]
    return paare, titel


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def swift_hilfsprogramm() -> Path:
    umgebung = dict(os.environ)
    umgebung.setdefault("DEVELOPER_DIR", "/Applications/Xcode.app/Contents/Developer")
    subprocess.run(["swift", "build", "--product", "SiegelStaerkeExport"], cwd=PAKET, env=umgebung, check=True,
                   stdout=subprocess.DEVNULL)
    pfad = subprocess.run(["swift", "build", "--show-bin-path"], cwd=PAKET, env=umgebung, check=True,
                          capture_output=True, text=True).stdout.strip()
    return Path(pfad) / "SiegelStaerkeExport"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ohne-swift", action="store_true", help="nur den Korpus schreiben, keine Erwartungswerte")
    parser.add_argument("--pruefen", action="store_true", help="nur prüfen, ob die Dateien aktuell sind")
    args = parser.parse_args()

    faelle = Korpus().bauen()
    if len(faelle) < 10_000:
        sys.exit(f"Korpus zu klein: {len(faelle)}")
    korpus = "# Siegel Stärke-Korpus (erfunden), Felder Base64: Passwort, Benutzereingaben…\n" + "".join(
        "\t".join([b64(p)] + [b64(e) for e in eingaben]) + "\n" for p, eingaben in faelle)
    graphem = "# Siegel Graphem-Korpus, Base64\n" + "".join(b64(t) + "\n" for t in graphem_korpus())
    paare, titel = url_korpus()
    autofill = "# Siegel Autofill-Korpus, Base64: Eintrag, Website\n" + "".join(
        b64(e) + "\t" + b64(d) + "\n" for e, d in paare)
    titel_text = "# Siegel Titel-Korpus (CSV-Titel aus der URL), Base64\n" + "".join(b64(t) + "\n" for t in titel)
    nfc_faelle = nfc_korpus()
    nfc_text = "# Siegel NFC-Korpus, Base64\n" + "".join(b64(t) + "\n" for t in nfc_faelle)
    gleich_text = "# Siegel Gleichheits-Korpus (Swift-String ==), Base64: a, b\n" + "".join(
        b64(a) + "\t" + b64(b) + "\n" for a, b in gleich_korpus(nfc_faelle))
    dateien = {DATEN / "staerke_korpus.txt.gz": gz(korpus.encode("utf-8")),
               DATEN / "graphem_korpus.txt.gz": gz(graphem.encode("utf-8")),
               DATEN / "autofill_korpus.txt.gz": gz(autofill.encode("utf-8")),
               DATEN / "titel_korpus.txt.gz": gz(titel_text.encode("utf-8")),
               DATEN / "nfc_korpus.txt.gz": gz(nfc_text.encode("utf-8")),
               DATEN / "gleich_korpus.txt.gz": gz(gleich_text.encode("utf-8"))}
    if not args.ohne_swift:
        programm = swift_hilfsprogramm()
        with tempfile.TemporaryDirectory() as ordner:
            k = Path(ordner) / "k.txt"
            e = Path(ordner) / "e.txt"
            k.write_text(korpus, encoding="utf-8")
            subprocess.run([str(programm), "bewerten", str(k), str(e), "--jahr", str(JAHR)], check=True)
            dateien[DATEN / "staerke_erwartet.txt.gz"] = gz(e.read_bytes())
            k.write_text(graphem, encoding="utf-8")
            subprocess.run([str(programm), "graphem", str(k), str(e)], check=True)
            dateien[DATEN / "graphem_erwartet.txt.gz"] = gz(e.read_bytes())
            k.write_text(autofill, encoding="utf-8")
            subprocess.run([str(programm), "autofill", str(k), str(e)], check=True)
            dateien[DATEN / "autofill_erwartet.txt.gz"] = gz(e.read_bytes())
            k.write_text(titel_text, encoding="utf-8")
            subprocess.run([str(programm), "titel", str(k), str(e)], check=True)
            dateien[DATEN / "titel_erwartet.txt.gz"] = gz(e.read_bytes())
            k.write_text(nfc_text, encoding="utf-8")
            subprocess.run([str(programm), "nfc-korpus", str(k), str(e)], check=True)
            dateien[DATEN / "nfc_erwartet.txt.gz"] = gz(e.read_bytes())
            k.write_text(gleich_text, encoding="utf-8")
            subprocess.run([str(programm), "gleich", str(k), str(e)], check=True)
            dateien[DATEN / "gleich_erwartet.txt.gz"] = gz(e.read_bytes())
    veraltet = [p for p, inhalt in dateien.items() if not p.is_file() or p.read_bytes() != inhalt]
    if args.pruefen:
        for p in veraltet:
            print(f"veraltet: {p.relative_to(PAKET)}")
        return 1 if veraltet else 0
    DATEN.mkdir(parents=True, exist_ok=True)
    for p, inhalt in dateien.items():
        if p in veraltet:
            p.write_bytes(inhalt)
            print(f"geschrieben: {p.relative_to(PAKET)}")
    print(f"{len(faelle)} Fälle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
