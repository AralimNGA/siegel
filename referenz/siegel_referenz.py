#!/usr/bin/env python3
"""Unabhängige Referenz-Implementierung für Siegel (SPEC.md §2, §13.1, §13.2, §19, §21).

Nur aus SPEC.md geschrieben, nicht aus dem Swift-Code abgeleitet. Nur Python-Standardbibliothek plus libsodium
per ctypes (Argon2id, XChaCha20-Poly1305, sodium_unpad, ChaCha20). Zweck: Gegenprobe zu den Swift-Dateien.

    siegel_referenz.py siegel DATEI [--nur-kopf] [--se HEX] [--karte HEX] [--fido HEX]
    siegel_referenz.py kdbx DATEI

Das Passwort kommt über die Standardeingabe (ein abschliessender Zeilenumbruch wird entfernt), nie als
Argument (sonst stünde es in der Prozessliste). Ausgabe: JSON auf stdout, inklusive Klartext – nur für
Testdateien mit erfundenen Einträgen benutzen. Fehler: Meldung mit festem Code auf stderr, Exit-Code 2.

Faktor-Geheimnisse (Format v2) als Hex, roh wie im Siegel-Kern (§22): --se = ECDH_SE (32 B),
--karte = q (32 B), --fido = hmac-secret-Ausgabe (32 B).

libsodium: /opt/homebrew/opt/libsodium/lib/libsodium.dylib (anders: Umgebungsvariable SIEGEL_LIBSODIUM).
Python: 3.12 (python.org) oder neuer; mit `-I` aufrufen.
"""

import base64
import ctypes
import gzip
import hashlib
import hmac
import json
import os
import struct
import sys
import unicodedata
import uuid
import xml.etree.ElementTree as ET

LIBSODIUM_STANDARD = "/opt/homebrew/opt/libsodium/lib/libsodium.dylib"


class ReferenzFehler(Exception):
    """Fehler mit festem Code (wie SiegelError: nie Inhalte im Text)."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


# --------------------------------------------------------------------------------------------------------------
# libsodium

class Sodium:
    def __init__(self, pfad):
        try:
            self.lib = ctypes.CDLL(pfad)
        except OSError:
            raise ReferenzFehler("libsodium.fehlt")
        if self.lib.sodium_init() < 0:
            raise ReferenzFehler("libsodium.init")
        L = self.lib
        L.crypto_pwhash.argtypes = [ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_ulonglong,
                                    ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_size_t, ctypes.c_int]
        L.crypto_pwhash.restype = ctypes.c_int
        L.crypto_pwhash_alg_argon2id13.restype = ctypes.c_int
        L.crypto_pwhash_saltbytes.restype = ctypes.c_size_t
        L.crypto_aead_xchacha20poly1305_ietf_decrypt.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p, ctypes.c_char_p,
            ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]
        L.crypto_aead_xchacha20poly1305_ietf_decrypt.restype = ctypes.c_int
        L.sodium_unpad.argtypes = [ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t]
        L.sodium_unpad.restype = ctypes.c_int
        L.crypto_stream_chacha20_ietf_xor.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong,
                                                      ctypes.c_char_p, ctypes.c_char_p]
        L.crypto_stream_chacha20_ietf_xor.restype = ctypes.c_int
        L.crypto_stream_chacha20_ietf.argtypes = [ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p,
                                                  ctypes.c_char_p]
        L.crypto_stream_chacha20_ietf.restype = ctypes.c_int
        self.argon2id13 = L.crypto_pwhash_alg_argon2id13()
        self.saltbytes = L.crypto_pwhash_saltbytes()

    def argon2id(self, passwort, salz, ops, mem):
        if len(salz) != self.saltbytes:
            raise ReferenzFehler("kdf.salz")
        out = ctypes.create_string_buffer(32)
        rc = self.lib.crypto_pwhash(out, 32, passwort, len(passwort), salz, ops, mem, self.argon2id13)
        if rc != 0:
            raise ReferenzFehler("kdf.fehlgeschlagen")
        return out.raw

    def xchacha_oeffnen(self, schluessel, nonce, geheimtext_mit_tag, ad):
        if len(geheimtext_mit_tag) < 16 or len(nonce) != 24 or len(schluessel) != 32:
            raise ReferenzFehler("aead.laenge")
        out = ctypes.create_string_buffer(len(geheimtext_mit_tag))
        mlen = ctypes.c_ulonglong(0)
        rc = self.lib.crypto_aead_xchacha20poly1305_ietf_decrypt(
            out, ctypes.byref(mlen), None, geheimtext_mit_tag, len(geheimtext_mit_tag), ad, len(ad), nonce, schluessel)
        if rc != 0:
            return None
        return out.raw[:mlen.value]

    def unpad(self, daten, block):
        laenge = ctypes.c_size_t(0)
        buf = ctypes.create_string_buffer(daten, len(daten))
        if self.lib.sodium_unpad(ctypes.byref(laenge), buf, len(daten), block) != 0:
            raise ReferenzFehler("inhalt.padding")
        return daten[:laenge.value]

    def chacha20_xor(self, daten, nonce12, schluessel32):
        out = ctypes.create_string_buffer(len(daten))
        if self.lib.crypto_stream_chacha20_ietf_xor(out, daten, len(daten), nonce12, schluessel32) != 0:
            raise ReferenzFehler("chacha20")
        return out.raw

    def chacha20_strom(self, laenge, nonce12, schluessel32):
        out = ctypes.create_string_buffer(max(laenge, 1))
        if laenge and self.lib.crypto_stream_chacha20_ietf(out, laenge, nonce12, schluessel32) != 0:
            raise ReferenzFehler("chacha20")
        return out.raw[:laenge]


# --------------------------------------------------------------------------------------------------------------
# Hilfen

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def crockford_msb(daten):
    """Crockford-Base32, MSB-first, ohne Füllzeichen (SPEC §1.5)."""
    bits = int.from_bytes(daten, "big")
    anzahl = (len(daten) * 8 + 4) // 5
    bits <<= anzahl * 5 - len(daten) * 8
    return "".join(CROCKFORD[(bits >> (5 * (anzahl - 1 - i))) & 31] for i in range(anzahl))


def sha3(*teile):
    h = hashlib.sha3_256()
    for t in teile:
        h.update(t)
    return h.digest()


def hkdf_sha512(ikm, salz, info, laenge):
    """RFC 5869 mit SHA-512 (Extract + Expand)."""
    prk = hmac.new(salz, ikm, hashlib.sha512).digest()
    ausgabe, block, zaehler = b"", b"", 1
    while len(ausgabe) < laenge:
        block = hmac.new(prk, block + info + bytes([zaehler]), hashlib.sha512).digest()
        ausgabe += block
        zaehler += 1
    return ausgabe[:laenge]


def passwort_abbilden(passwort):
    """RFC 8265 OpaqueString wie SPEC §1.1: Zs (ausser U+0020) → U+0020, dann NFC, nichts trimmen."""
    abgebildet = "".join(" " if unicodedata.category(z) == "Zs" else z for z in passwort)
    return unicodedata.normalize("NFC", abgebildet)


class Leser:
    def __init__(self, daten):
        self.daten = daten
        self.pos = 0

    def bytes(self, n):
        if n < 0 or self.pos + n > len(self.daten):
            raise ReferenzFehler("datei.kurz")
        teil = self.daten[self.pos:self.pos + n]
        self.pos += n
        return teil

    def u8(self):
        return self.bytes(1)[0]

    def u16(self):
        return struct.unpack("<H", self.bytes(2))[0]

    def u32(self):
        return struct.unpack("<I", self.bytes(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.bytes(8))[0]


# --------------------------------------------------------------------------------------------------------------
# .siegel Version 1 und 2 (SPEC §2, §13.2)

PKM_LAENGE = 1568
PKX_LAENGE = 32
SLOTS_LAENGE = 72 + 1568 + 32 + 72
CT_MIN = 16400
CT_MAX = 64 * 1024 * 1024
KDF_MEM_MIN = 256 * 1024 * 1024
KDF_MEM_MAX = 4 * 1024 * 1024 * 1024
KDF_OPS_MIN, KDF_OPS_MAX = 3, 10


def kopf_lesen(daten):
    """KOPF v1/v2 → (Felder, Kopf-Bytes). Prüft Grenzen und Konsistenz (ohne Geheimnis)."""
    r = Leser(daten)
    if r.bytes(6) != b"SIEGEL":
        raise ReferenzFehler("header.magic")
    version = r.u16()
    if version not in (1, 2):
        raise ReferenzFehler("header.version")
    k = {"formatVersion": version}
    k["vaultID"] = r.bytes(16)
    if r.u8() != 1:
        raise ReferenzFehler("header.kdfAlg")
    k["opsLimit"] = r.u32()
    k["memLimitBytes"] = r.u64()
    k["kdfSalt"] = r.bytes(16)
    if not (KDF_MEM_MIN <= k["memLimitBytes"] <= KDF_MEM_MAX and k["memLimitBytes"] % 1024 == 0
            and KDF_OPS_MIN <= k["opsLimit"] <= KDF_OPS_MAX):
        raise ReferenzFehler("kdfParametersOutOfRange")
    k["factorMask"], k["recoveryScheme"] = 0, 1
    k["seKeyID"], k["cardTag"], k["fidoCredentialID"], k["fidoSalt"] = None, None, None, None
    if version == 2:
        maske = r.u8()
        if maske & ~0x07:
            raise ReferenzFehler("header.factorMask")
        schema = r.u8()
        if schema not in (1, 2):
            raise ReferenzFehler("header.recoveryScheme")
        se_id = r.bytes(16)
        karten_tag = r.bytes(4)
        fido_laenge = r.u16()
        fido_id = r.bytes(fido_laenge)
        fido_salz = r.bytes(32)
        # Konsistenz Maske ↔ Nullfelder
        if not maske & 1 and se_id != bytes(16):
            raise ReferenzFehler("header.seKeyID")
        if not maske & 2 and karten_tag != bytes(4):
            raise ReferenzFehler("header.cardTag")
        if maske & 4:
            if not 16 <= fido_laenge <= 1024:
                raise ReferenzFehler("header.fidoCredential")
        elif fido_laenge != 0 or fido_salz != bytes(32):
            raise ReferenzFehler("header.fidoCredential")
        k["factorMask"], k["recoveryScheme"] = maske, schema
        k["seKeyID"] = se_id if maske & 1 else None
        k["cardTag"] = karten_tag if maske & 2 else None
        k["fidoCredentialID"] = fido_id if maske & 4 else None
        k["fidoSalt"] = fido_salz if maske & 4 else None
    k["pkM"] = r.bytes(PKM_LAENGE)
    k["pkX"] = r.bytes(PKX_LAENGE)
    return k, daten[:r.pos]


def label(version, text):
    return ("Siegel v%d " % version + text).encode("ascii")


def kit_kennung(version, pkm, pkx):
    # SPEC §13.2 (v4.1): "kit id" und "recovery checksum" gehören zum gedruckten Kit und heissen in allen
    # Formatversionen "Siegel v1 …" – sonst passte ein gedrucktes Blatt nach der Umstellung v1 → v2 nicht mehr.
    roh = crockford_msb(sha3(label(1, "kit id"), pkm, pkx)[:5])
    return roh[:4] + "-" + roh[4:]


def siegel_lesen(sodium, daten, passwort, faktoren, nur_kopf):
    # Prüfsumme zuerst (§2): vor jeder Ableitung
    if len(daten) < 6 + 2 + 32:
        raise ReferenzFehler("file.length")
    version = struct.unpack("<H", daten[6:8])[0] if daten[:6] == b"SIEGEL" else None
    if version not in (1, 2):
        kopf_lesen(daten)                 # wirft den passenden Fehler
    rumpf, pruefsumme = daten[:-32], daten[-32:]
    if not hmac.compare_digest(sha3(label(version, "file check"), rumpf), pruefsumme):
        raise ReferenzFehler("file.checksum")

    k, kopf = kopf_lesen(rumpf)
    r = Leser(rumpf)
    r.pos = len(kopf)
    slots = r.bytes(SLOTS_LAENGE)
    generation = r.u64()
    nonce = r.bytes(24)
    ct_laenge = r.u32()
    if not CT_MIN <= ct_laenge <= CT_MAX:
        raise ReferenzFehler("payload.length")
    geheimtext = r.bytes(ct_laenge)
    if r.pos != len(rumpf):
        raise ReferenzFehler("file.trailing")

    ergebnis = {
        "formatVersion": version,
        "vaultID": str(uuid.UUID(bytes=k["vaultID"])).upper(),
        "kitID": kit_kennung(version, k["pkM"], k["pkX"]),
        "kdf": {"opsLimit": k["opsLimit"], "memLimitBytes": k["memLimitBytes"]},
        "factorMask": k["factorMask"],
        "recoveryScheme": k["recoveryScheme"],
        "seKeyID": str(uuid.UUID(bytes=k["seKeyID"])).upper() if k["seKeyID"] else None,
        "cardTag": k["cardTag"].hex() if k["cardTag"] else None,
        "fidoCredentialID": k["fidoCredentialID"].hex() if k["fidoCredentialID"] else None,
        "fidoSalt": k["fidoSalt"].hex() if k["fidoSalt"] else None,
        "generation": generation,
        "dateigroesse": len(daten),
    }
    if nur_kopf:
        return ergebnis

    # Faktoren: fehlende vor jeder Rechnung melden, Karte vorab an der Karten-Kennung prüfen (§13.1, §14.2)
    maske = k["factorMask"]
    for bit, name in ((1, "se"), (2, "karte"), (4, "fido")):
        if maske & bit and faktoren.get(name) is None:
            raise ReferenzFehler("factorMissing." + name)
    if maske & 2:
        tag = sha3(b"Siegel v2 card tag", k["vaultID"], faktoren["karte"])[:4]
        if tag != k["cardTag"]:
            raise ReferenzFehler("wrongCard")

    # Passwortweg
    pw = passwort_abbilden(passwort).encode("utf-8")
    p = sodium.argon2id(pw, k["kdfSalt"], k["opsLimit"], k["memLimitBytes"])
    if version == 1:
        kek = p
    else:
        ikm = p
        if maske & 1:
            ikm += hkdf_sha512(faktoren["se"], k["vaultID"], b"Siegel v2 factor secure-enclave", 32)
        if maske & 2:
            ikm += hkdf_sha512(faktoren["karte"], k["vaultID"], b"Siegel v2 factor card", 32)
        if maske & 4:
            ikm += hkdf_sha512(faktoren["fido"], k["vaultID"], b"Siegel v2 factor fido2", 32)
        kek = hkdf_sha512(ikm, k["kdfSalt"], b"Siegel v2 kek" + bytes([maske]), 32)

    pw_slot = slots[:72]
    dek = sodium.xchacha_oeffnen(kek, pw_slot[:24], pw_slot[24:], label(version, "slot pw") + kopf)
    if dek is None or len(dek) != 32:
        raise ReferenzFehler("wrongPassword")

    ad = label(version, "payload") + kopf + slots + struct.pack("<Q", generation)
    gepolstert = sodium.xchacha_oeffnen(dek, nonce, geheimtext, ad)
    if gepolstert is None:
        raise ReferenzFehler("corruptFile.payload")
    klartext = sodium.unpad(gepolstert, 16384)
    try:
        ergebnis["inhalt"] = json.loads(klartext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ReferenzFehler("corruptFile.json")
    return ergebnis


# --------------------------------------------------------------------------------------------------------------
# KDBX 4.x (SPEC §19)

KDBX_SIG1, KDBX_SIG2 = 0x9AA2D903, 0xB54BFB67
CIPHER_CHACHA20 = bytes.fromhex("D6038A2B8B6F4CB5A524339A31DBB59A")
KDF_ARGON2ID = bytes.fromhex("9E298B1956DB4773B23DFC3EC6F0A1E6")
KDF_ARGON2D = bytes.fromhex("EF636DDF8C29444B91F7A9A403E30A0C")
EPOCHE_0001 = 62135596800


def variant_dictionary(daten):
    r = Leser(daten)
    if r.u16() >> 8 != 1:
        raise ReferenzFehler("kdbx.vd.version")
    werte = {}
    while True:
        typ = r.u8()
        if typ == 0:
            break
        name = r.bytes(r.u32()).decode("utf-8")
        wert = r.bytes(r.u32())
        if typ == 0x04:
            wert = struct.unpack("<I", wert)[0]
        elif typ == 0x05:
            wert = struct.unpack("<Q", wert)[0]
        elif typ == 0x08:
            wert = wert != b"\x00"
        elif typ == 0x0C:
            wert = struct.unpack("<i", wert)[0]
        elif typ == 0x0D:
            wert = struct.unpack("<q", wert)[0]
        elif typ == 0x18:
            wert = wert.decode("utf-8")
        elif typ != 0x42:
            raise ReferenzFehler("kdbx.vd.typ")
        werte[name] = wert
    if r.pos != len(daten):
        raise ReferenzFehler("kdbx.vd.rest")
    return werte


def kdbx_zeit(text):
    if not text:
        return None
    roh = base64.b64decode(text, validate=True)
    if len(roh) != 8:
        raise ReferenzFehler("kdbx.zeit")
    sekunden = struct.unpack("<q", roh)[0] - EPOCHE_0001
    return sekunden


def kdbx_lesen(sodium, daten, passwort):
    r = Leser(daten)
    if r.u32() != KDBX_SIG1 or r.u32() != KDBX_SIG2:
        raise ReferenzFehler("kdbx.signatur")
    version = r.u32()
    if version >> 16 != 4:
        raise ReferenzFehler("kdbx.version")
    felder = {}
    while True:
        fid = r.u8()
        wert = r.bytes(r.u32())
        if fid in felder:
            raise ReferenzFehler("kdbx.kopf.doppelt")
        felder[fid] = wert
        if fid == 0:
            break
    kopf = daten[:r.pos]
    if not hmac.compare_digest(hashlib.sha256(kopf).digest(), r.bytes(32)):
        raise ReferenzFehler("kdbx.kopf.hash")
    kopf_hmac = r.bytes(32)

    if felder.get(2) != CIPHER_CHACHA20:
        raise ReferenzFehler("kdbx.cipher")          # AES-CBC/Twofish: nicht in der Standardbibliothek
    kompression = struct.unpack("<I", felder.get(3, b"\0\0\0\0"))[0]
    seed, iv = felder.get(4, b""), felder.get(7, b"")
    if len(seed) != 32 or len(iv) != 12:
        raise ReferenzFehler("kdbx.kopf.felder")
    kdf = variant_dictionary(felder.get(11, b""))
    if kdf.get("$UUID") == KDF_ARGON2D:
        raise ReferenzFehler("kdbx.kdf.argon2d")     # libsodium kennt nur Argon2id/Argon2i
    if kdf.get("$UUID") != KDF_ARGON2ID or kdf.get("P") != 1 or kdf.get("V") != 0x13:
        raise ReferenzFehler("kdbx.kdf.parameter")
    if kdf.get("K") or kdf.get("A"):
        raise ReferenzFehler("kdbx.kdf.geheimnis")

    zusammengesetzt = hashlib.sha256(hashlib.sha256(passwort.encode("utf-8")).digest()).digest()
    transformiert = sodium.argon2id(zusammengesetzt, kdf["S"], kdf["I"], kdf["M"])
    hmac_basis = hashlib.sha512(seed + transformiert + b"\x01").digest()

    def block_schluessel(index):
        return hashlib.sha512(struct.pack("<Q", index) + hmac_basis).digest()

    if not hmac.compare_digest(hmac.new(block_schluessel(0xFFFFFFFFFFFFFFFF), kopf, hashlib.sha256).digest(), kopf_hmac):
        raise ReferenzFehler("kdbx.passwortOderKopf")

    geheimtext, index = b"", 0
    while True:
        mac = r.bytes(32)
        laenge_roh = r.bytes(4)
        laenge = struct.unpack("<i", laenge_roh)[0]
        if laenge < 0:
            raise ReferenzFehler("kdbx.block.laenge")
        block = r.bytes(laenge)
        erwartet = hmac.new(block_schluessel(index), struct.pack("<Q", index) + laenge_roh + block, hashlib.sha256).digest()
        if not hmac.compare_digest(erwartet, mac):
            raise ReferenzFehler("kdbx.block.hmac")
        index += 1
        if laenge == 0:
            break
        geheimtext += block
    if r.pos != len(daten):
        raise ReferenzFehler("kdbx.restbytes")

    klartext = sodium.chacha20_xor(geheimtext, iv, hashlib.sha256(seed + transformiert).digest())
    if kompression == 1:
        klartext = gzip.decompress(klartext)
    elif kompression != 0:
        raise ReferenzFehler("kdbx.kompression")

    innen = Leser(klartext)
    innere = {}
    while True:
        fid = innen.u8()
        wert = innen.bytes(innen.u32())
        if fid == 0:
            break
        if fid != 3:                                   # 3 = Anhang (Binary), mehrfach erlaubt
            innere[fid] = wert
    if struct.unpack("<I", innere.get(1, b"\0\0\0\0"))[0] != 3 or len(innere.get(2, b"")) != 64:
        raise ReferenzFehler("kdbx.innererStrom")
    xml_bytes = klartext[innen.pos:]
    if b"<!DOCTYPE" in xml_bytes or b"<!ENTITY" in xml_bytes:
        raise ReferenzFehler("kdbx.xml.doctype")
    try:
        wurzel = ET.fromstring(xml_bytes)
    except ET.ParseError:
        raise ReferenzFehler("kdbx.xml")

    # Geschützte Werte in Dokumentreihenfolge mit einem fortlaufenden ChaCha20-Strom
    strom_hash = hashlib.sha512(innere[2]).digest()
    geschuetzt = [e for e in wurzel.iter("Value") if e.get("Protected") == "True"]
    roh = [base64.b64decode(e.text or "", validate=True) for e in geschuetzt]
    strom = sodium.chacha20_strom(sum(len(x) for x in roh), strom_hash[32:44], strom_hash[:32])
    klar, versatz = {}, 0
    for element, daten_roh in zip(geschuetzt, roh):
        klar[id(element)] = bytes(a ^ b for a, b in zip(daten_roh, strom[versatz:versatz + len(daten_roh)])).decode("utf-8")
        versatz += len(daten_roh)

    def gruppe_lesen(g):
        ergebnis = {"name": g.findtext("Name") or "", "eintraege": [], "gruppen": []}
        for e in g.findall("Entry"):
            werte, geschuetzte_felder = {}, []
            for s in e.findall("String"):
                schluessel = s.findtext("Key")
                wert = s.find("Value")
                if wert is not None and wert.get("Protected") == "True":
                    werte[schluessel] = klar[id(wert)]
                    geschuetzte_felder.append(schluessel)
                else:
                    werte[schluessel] = (wert.text or "") if wert is not None else ""
            zeiten = e.find("Times")
            ergebnis["eintraege"].append({
                "uuid": str(uuid.UUID(bytes=base64.b64decode(e.findtext("UUID") or ""))).upper(),
                "werte": werte,
                "geschuetzt": sorted(geschuetzte_felder),
                "erstellt": kdbx_zeit(zeiten.findtext("CreationTime")) if zeiten is not None else None,
                "geaendert": kdbx_zeit(zeiten.findtext("LastModificationTime")) if zeiten is not None else None,
                "verlauf": len(e.findall("History/Entry")),
            })
        for unter in g.findall("Group"):
            ergebnis["gruppen"].append(gruppe_lesen(unter))
        return ergebnis

    root_gruppe = wurzel.find("Root/Group")
    if root_gruppe is None:
        raise ReferenzFehler("kdbx.xml.root")
    return {
        "version": "%d.%d" % (version >> 16, version & 0xFFFF),
        "kdf": {"I": kdf["I"], "M": kdf["M"], "P": kdf["P"], "salzLaenge": len(kdf["S"])},
        "kompression": kompression,
        "bloecke": index,
        "generator": wurzel.findtext("Meta/Generator"),
        "gruppe": gruppe_lesen(root_gruppe),
    }


# --------------------------------------------------------------------------------------------------------------
# Kommandozeile

def faktor_hex(text, name):
    if text is None:
        return None
    try:
        roh = bytes.fromhex(text)
    except ValueError:
        raise ReferenzFehler("faktor.hex." + name)
    if len(roh) != 32:
        raise ReferenzFehler("faktor.laenge." + name)
    return roh


def main(argv):
    if len(argv) < 3 or argv[1] not in ("siegel", "kdbx"):
        sys.stderr.write(__doc__)
        return 64
    art, pfad, optionen = argv[1], argv[2], argv[3:]
    nur_kopf = "--nur-kopf" in optionen
    faktoren = {}
    i = 0
    while i < len(optionen):
        o = optionen[i]
        if o in ("--se", "--karte", "--fido") and i + 1 < len(optionen):
            faktoren[o[2:]] = faktor_hex(optionen[i + 1], o[2:])
            i += 2
        elif o == "--nur-kopf":
            i += 1
        else:
            raise ReferenzFehler("argument")
    with open(pfad, "rb") as f:
        daten = f.read(CT_MAX + 1024 * 1024)
    sodium = Sodium(os.environ.get("SIEGEL_LIBSODIUM", LIBSODIUM_STANDARD))
    passwort = ""
    if not nur_kopf:
        passwort = sys.stdin.buffer.read().decode("utf-8")
        if passwort.endswith("\n"):
            passwort = passwort[:-1]
    if art == "siegel":
        ergebnis = siegel_lesen(sodium, daten, passwort, faktoren, nur_kopf)
    else:
        ergebnis = kdbx_lesen(sodium, daten, passwort)
    sys.stdout.write(json.dumps(ergebnis, ensure_ascii=False, sort_keys=True, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except ReferenzFehler as fehler:
        sys.stderr.write("FEHLER " + fehler.code + "\n")
        sys.exit(2)
