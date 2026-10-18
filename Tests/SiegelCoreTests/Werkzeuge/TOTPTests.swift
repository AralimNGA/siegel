import Foundation
import Testing
@testable import SiegelCore

// Tests für TOTP (SPEC §18): Testvektoren aus RFC 6238 Anhang B (alle drei Algorithmen) und RFC 4226 Anhang D,
// toleranter Base32-Leser, strenger otpauth-Parser mit Grenzen, Fehlercodes, Schwärzung.

private func invalid(_ code: String) -> SiegelError { .totpInvalid(code) }

/// RFC 6238 Anhang B: ASCII-Seeds je Algorithmus (20/32/64 Byte), als Base32.
private let seedSHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
private let seedSHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
private let seedSHA512 = String(repeating: "GEZDGNBVGY3TQOJQ", count: 6) + "GEZDGNA="

private func uri(_ seed: String, _ algorithm: String) -> String {
    "otpauth://totp/RFC6238:test?secret=\(seed)&algorithm=\(algorithm)&digits=8&period=30"
}

@Suite("TOTP: Testvektoren")
struct TOTPVectorTests {

    /// (Zeit, SHA1, SHA256, SHA512) aus RFC 6238 Anhang B.
    static let vectors: [(Int64, String, String, String)] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ]

    @Test("RFC 6238 Anhang B: SHA1, SHA256, SHA512 mit 8 Ziffern")
    func rfc6238() throws {
        let sha1 = try TOTP.parse(uri(seedSHA1, "SHA1"))
        let sha256 = try TOTP.parse(uri(seedSHA256, "SHA256"))
        let sha512 = try TOTP.parse(uri(seedSHA512, "SHA512"))
        #expect(sha1.algorithm == .sha1 && sha256.algorithm == .sha256 && sha512.algorithm == .sha512)
        #expect(sha1.secretByteCount == 20 && sha256.secretByteCount == 32 && sha512.secretByteCount == 64)
        for (time, expected1, expected256, expected512) in Self.vectors {
            let date = Date(timeIntervalSince1970: TimeInterval(time))
            let remaining = Int(30 - time % 30)
            #expect(TOTP.code(sha1, at: date) == (expected1, remaining))
            #expect(TOTP.code(sha256, at: date).code == expected256)
            #expect(TOTP.code(sha512, at: date).code == expected512)
        }
    }

    @Test("RFC 4226 Anhang D: HOTP-Werte für Zähler 0…9")
    func rfc4226() throws {
        let expected = ["755224", "287082", "359152", "969429", "338314",
                        "254676", "287922", "162583", "399871", "520489"]
        let parameters = try TOTP.parse(seedSHA1)
        for (counter, value) in expected.enumerated() {
            #expect(TOTP.hotp(key: parameters.key, counter: UInt64(counter), digits: 6, algorithm: .sha1) == value)
        }
    }

    @Test("Restsekunden, Periodengrenzen, Zeit vor 1970")
    func restsekunden() throws {
        let parameters = try TOTP.parse("otpauth://totp/x?secret=\(seedSHA1)&period=60")
        #expect(TOTP.code(parameters, at: Date(timeIntervalSince1970: 120)).remaining == 60)
        #expect(TOTP.code(parameters, at: Date(timeIntervalSince1970: 179.9)).remaining == 1)
        // Gleiche Periode → gleicher Code, nächste Periode → (fast sicher) anderer Code.
        let a = TOTP.code(parameters, at: Date(timeIntervalSince1970: 120)).code
        let b = TOTP.code(parameters, at: Date(timeIntervalSince1970: 179)).code
        #expect(a == b)
        // Vor 1970 und unendlich gelten als Zähler 0.
        let zero = TOTP.hotp(key: parameters.key, counter: 0, digits: 6, algorithm: .sha1)
        #expect(TOTP.code(parameters, at: Date(timeIntervalSince1970: -5000)).code == zero)
        #expect(TOTP.code(parameters, at: Date(timeIntervalSince1970: .infinity)).code == zero)
        #expect(TOTP.code(parameters, at: Date(timeIntervalSince1970: .nan)).code == zero)
        for t in stride(from: 0.0, to: 200.0, by: 7.3) {
            let r = TOTP.code(parameters, at: Date(timeIntervalSince1970: t)).remaining
            #expect((1...60).contains(r))
        }
    }

    @Test("6 Ziffern mit führenden Nullen")
    func fuehrendeNullen() throws {
        // RFC 6238, t = 1111111109, SHA1: 07081804 → 6 Ziffern = 081804
        let parameters = try TOTP.parse("otpauth://totp/x?secret=\(seedSHA1)")
        #expect(parameters.digits == 6)
        #expect(TOTP.code(parameters, at: Date(timeIntervalSince1970: 1_111_111_109)).code == "081804")
    }
}

@Suite("TOTP: Base32 und URI-Parser")
struct TOTPParserTests {

    @Test("Base32 tolerant: Kleinbuchstaben, Leerraum, Padding fehlt oder vollständig")
    func base32Tolerant() throws {
        let reference = try TOTP.parse("JBSWY3DPEHPK3PXP")
        #expect(reference.secretByteCount == 10)
        #expect(reference.algorithm == .sha1 && reference.digits == 6 && reference.period == 30)
        for variant in ["jbswy3dpehpk3pxp", "JBSW Y3DP EHPK 3PXP", "  jbsw y3dp\tehpk 3pxp \n", "JbSwY3dPeHpK3pXp"] {
            #expect(try TOTP.parse(variant) == reference)
        }
        // 11 Byte: mit und ohne Padding gleich
        let padded = try TOTP.parse("AAAQEAYEAUDAOCAJBI======")
        let unpadded = try TOTP.parse("aaaqeayeaudaocajbi")
        #expect(padded == unpadded)
        #expect(padded.secretByteCount == 11)
        // SHA256-Seed mit Padding mitten in der URI und ohne
        #expect(try TOTP.parse(uri(seedSHA256, "SHA256")) == TOTP.parse(uri(String(seedSHA256.dropLast(4)), "SHA256")))
    }

    @Test("Base32 streng, wo nötig: falsches Alphabet, Padding falsch, Länge unmöglich")
    func base32Fehler() {
        #expect(throws: invalid("totp.base32")) { try TOTP.parse("JBSWY3DPEHPK3PX1") }        // 1 nicht im Alphabet
        #expect(throws: invalid("totp.base32")) { try TOTP.parse("JBSWY3DPEHPK3PX8") }        // 8 ebenso
        #expect(throws: invalid("totp.base32")) { try TOTP.parse("JBSWY3DP=EHPK3PXP") }       // Padding mitten drin
        #expect(throws: invalid("totp.base32")) { try TOTP.parse("AAAQEAYEAUDAOCAJBI===") }   // Padding unvollständig
        #expect(throws: invalid("totp.base32")) { try TOTP.parse("JBSWY3DPEHPK3PXP========") } // Padding zu viel
        #expect(throws: invalid("totp.base32")) { try TOTP.parse("JBSWY3DPEHPK3PXPA") }       // 17 Zeichen: Rest 1
        #expect(throws: invalid("totp.base32")) { try TOTP.parse("JBSWY3DPEHPK3PXPAAA") }     // Rest 3
        #expect(throws: invalid("totp.base32")) { try TOTP.parse("JBSWY3DP-EHPK3PXP") }       // Bindestrich
        #expect(throws: invalid("totp.base32")) { try TOTP.parse("JBSWY3DPEHPK3PXPÄ") }
    }

    @Test("Geheimnis 10–128 Byte")
    func geheimnisLaenge() throws {
        #expect(throws: invalid("totp.secret.length")) { try TOTP.parse("JBSWY3DP") }                // 5 Byte
        #expect(throws: invalid("totp.secret.length")) { try TOTP.parse("JBSWY3DPEHPK3PY") } // Rest 7 → 9 Byte
        let maximum = String(repeating: "A", count: 128 * 8 / 5)       // 204 Zeichen = 127.5 → 127 Byte
        #expect(try TOTP.parse(maximum).secretByteCount == 127)
        let tooLong = String(repeating: "AAAAAAAA", count: 25) + "AAAAAAA"   // 207 Zeichen → 129 Byte
        #expect(throws: invalid("totp.secret.length")) { try TOTP.parse(tooLong) }
        #expect(throws: invalid("totp.secret.length")) {
            try TOTP.Parameters(secret: Data(count: 9))
        }
        #expect(throws: invalid("totp.secret.length")) {
            try TOTP.Parameters(secret: Data(count: 129))
        }
        #expect(try TOTP.Parameters(secret: Data(count: 128)).secretByteCount == 128)
    }

    @Test("Google-Beispiel: Aussteller aus Parameter und Label, Konto, Standardwerte")
    func googleBeispiel() throws {
        let p = try TOTP.parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
        #expect(p.issuer == "Example")
        #expect(p.account == "alice@google.com")
        #expect(p.algorithm == .sha1 && p.digits == 6 && p.period == 30)
        #expect(p == (try TOTP.parse("JBSWY3DPEHPK3PXP").withLabel(issuer: "Example", account: "alice@google.com")))

        let q = try TOTP.parse("OTPAUTH://TOTP/ACME%20Co:%20john.doe@email.com?SECRET=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
                               + "&Issuer=ACME%20Co&algorithm=sha256&digits=8&period=60&image=https%3A%2F%2Fx.example%2Fa.png")
        #expect(q.issuer == "ACME Co")
        #expect(q.account == "john.doe@email.com")
        #expect(q.algorithm == .sha256 && q.digits == 8 && q.period == 60)

        // Ohne Doppelpunkt: nur Konto; ohne Label; issuer-Parameter gewinnt über das Label.
        #expect(try TOTP.parse("otpauth://totp/anna?secret=JBSWY3DPEHPK3PXP").account == "anna")
        #expect(try TOTP.parse("otpauth://totp?secret=JBSWY3DPEHPK3PXP").account == "")
        let r = try TOTP.parse("otpauth://totp/Alt:anna?secret=JBSWY3DPEHPK3PXP&issuer=Neu")
        #expect(r.issuer == "Neu" && r.account == "anna")
        // Leerzeichen im Label unkodiert, '+' bleibt '+', Base32 im Geheimnis mit %20
        let s = try TOTP.parse("otpauth://totp/Mein Dienst:a+b?secret=JBSW%20Y3DP%20EHPK%203PXP")
        #expect(s.issuer == "Mein Dienst" && s.account == "a+b")
        #expect(s == (try TOTP.parse("JBSWY3DPEHPK3PXP").withLabel(issuer: "Mein Dienst", account: "a+b")))
    }

    @Test("Ziffern genau 6 oder 8, Periode 15–120, Algorithmen")
    func grenzen() throws {
        let base = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
        #expect(try TOTP.parse(base + "&digits=8").digits == 8)
        #expect(try TOTP.parse(base + "&digits=06").digits == 6)
        for bad in ["7", "5", "9", "10", "", "6a", "-6", "+6", "6.0", "0006"] {
            #expect(throws: invalid("totp.digits")) { try TOTP.parse(base + "&digits=\(bad)") }
        }
        #expect(try TOTP.parse(base + "&period=15").period == 15)
        #expect(try TOTP.parse(base + "&period=120").period == 120)
        for bad in ["14", "121", "0", "", "30s", "1000", "-30"] {
            #expect(throws: invalid("totp.period")) { try TOTP.parse(base + "&period=\(bad)") }
        }
        for bad in ["MD5", "SHA-1", "SHA384", "", "sha3"] {
            #expect(throws: invalid("totp.algorithm")) { try TOTP.parse(base + "&algorithm=\(bad)") }
        }
        #expect(throws: invalid("totp.digits")) { try TOTP.Parameters(secret: Data(count: 10), digits: 7) }
        #expect(throws: invalid("totp.period")) { try TOTP.Parameters(secret: Data(count: 10), period: 10) }
    }

    @Test("Strenger URI-Parser: Fehlercodes")
    func uriFehler() {
        #expect(throws: invalid("totp.empty")) { try TOTP.parse("") }
        #expect(throws: invalid("totp.empty")) { try TOTP.parse(" \n\t ") }
        #expect(throws: invalid("totp.tooLong")) { try TOTP.parse(String(repeating: "A", count: 2049)) }
        #expect(throws: invalid("totp.type")) { try TOTP.parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1") }
        #expect(throws: invalid("totp.type")) { try TOTP.parse("otpauth://steam/x?secret=JBSWY3DPEHPK3PXP") }
        #expect(throws: invalid("totp.secret.missing")) { try TOTP.parse("otpauth://totp/x?issuer=A") }
        #expect(throws: invalid("totp.secret.missing")) { try TOTP.parse("otpauth://totp/x?secret=") }
        #expect(throws: invalid("totp.secret.missing")) { try TOTP.parse("otpauth://totp/x") }
        #expect(throws: invalid("totp.duplicate")) {
            try TOTP.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=GEZDGNBVGY3TQOJQ")
        }
        #expect(throws: invalid("totp.duplicate")) {
            try TOTP.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6&DIGITS=8")
        }
        #expect(throws: invalid("totp.uri")) { try TOTP.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP#frag") }
        #expect(throws: invalid("totp.uri")) { try TOTP.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&lock") }
        #expect(throws: invalid("totp.uri")) { try TOTP.parse("otpauth://totp/x%G1?secret=JBSWY3DPEHPK3PXP") }
        #expect(throws: invalid("totp.uri")) { try TOTP.parse("otpauth://totp/x%4?secret=JBSWY3DPEHPK3PXP") }
        #expect(throws: invalid("totp.uri")) { try TOTP.parse("otpauth://totp/%FF%FE?secret=JBSWY3DPEHPK3PXP") }
        #expect(throws: invalid("totp.uri")) { try TOTP.parse("otpauth-migration://offline?data=CjEKCkhlbGxv") }
        #expect(throws: invalid("totp.uri")) { try TOTP.parse("https://example.com/?secret=JBSWY3DPEHPK3PXP") }
        let many = (0..<33).map { "x\($0)=1" }.joined(separator: "&")
        #expect(throws: invalid("totp.uri")) { try TOTP.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&" + many) }
        let longIssuer = String(repeating: "a", count: 257)
        #expect(throws: invalid("totp.label")) {
            try TOTP.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=\(longIssuer)")
        }
        #expect(throws: invalid("totp.label")) { try TOTP.parse("otpauth://totp/a:\(longIssuer)?secret=JBSWY3DPEHPK3PXP") }
    }

    @Test("Steuer- und Richtungszeichen aus Aussteller und Konto entfernt")
    func steuerzeichen() throws {
        let p = try TOTP.parse("otpauth://totp/Bank%E2%80%AEevil:an%00na?secret=JBSWY3DPEHPK3PXP")
        #expect(p.issuer == "Bankevil")
        #expect(p.account == "anna")
    }

    @Test("Alle geworfenen Codes stehen in der festen Liste")
    func codesFest() {
        #expect(Set(TOTP.reasonCodes).count == TOTP.reasonCodes.count)
        let inputs = ["", String(repeating: "A", count: 3000), "otpauth://hotp/x", "otpauth://totp/x",
                      "JBSWY3DP1", "JBSWY3DP", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=x",
                      "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=1",
                      "otpauth://totp/x?secret=A&secret=B", "otpauth://totp/x#", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer="
                        + String(repeating: "b", count: 300)]
        var seen = Set<String>()
        for input in inputs {
            do {
                _ = try TOTP.parse(input)
            } catch let SiegelError.totpInvalid(code) {
                seen.insert(code)
                #expect(TOTP.reasonCodes.contains(code))
            } catch {
                Issue.record("unerwarteter Fehler")
            }
        }
        #expect(seen.count == 12)
    }

    @Test("Zufallseingaben: kein Absturz, nur feste Codes")
    func zufall() {
        let alphabet = Array("otpauth:/?&=%#ABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdefghijklmnopqrstuvwxyz0189 -+.\u{0}\u{202E}é")
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<3000 {
            let length = Int.random(in: 0...80, using: &generator)
            var text = Bool.random(using: &generator) ? "otpauth://totp/" : ""
            for _ in 0..<length { text.append(alphabet[Int.random(in: 0..<alphabet.count, using: &generator)]) }
            do {
                let p = try TOTP.parse(text)
                #expect(TOTP.allowedDigits.contains(p.digits) && TOTP.allowedPeriods.contains(p.period))
                #expect((TOTP.minimumSecretBytes...TOTP.maximumSecretBytes).contains(p.secretByteCount))
            } catch let SiegelError.totpInvalid(code) {
                #expect(TOTP.reasonCodes.contains(code))
            } catch {
                Issue.record("unerwarteter Fehler")
            }
        }
    }

    @Test("Gleichheit vergleicht das Geheimnis; Beschreibung ist geschwärzt")
    func gleichheitUndSchwaerzung() throws {
        let a = try TOTP.parse("JBSWY3DPEHPK3PXP")
        let b = try TOTP.parse("GEZDGNBVGY3TQOJQ")
        #expect(a != b)
        #expect(a == (try TOTP.Parameters(secret: Data([0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF]))))
        let p = try TOTP.parse("otpauth://totp/Geheimdienst:anna?secret=JBSWY3DPEHPK3PXP")
        var dumped = ""
        dump(p, to: &dumped)
        for text in [String(describing: p), String(reflecting: p), dumped] {
            #expect(!text.contains("JBSWY3DP"))
            #expect(!text.contains("Hello"))
            #expect(!text.contains("anna"))
        }
    }
}

extension TOTP.Parameters {
    /// Nur Tests: gleiche Parameter mit anderem Label.
    func withLabel(issuer: String, account: String) throws -> TOTP.Parameters {
        try TOTP.Parameters(key: key, algorithm: algorithm, digits: digits, period: period, issuer: issuer, account: account)
    }
}
