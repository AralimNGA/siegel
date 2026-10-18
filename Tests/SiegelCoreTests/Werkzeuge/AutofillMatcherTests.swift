import Foundation
import Testing
@testable import SiegelCore

// Tests für AutofillMatcher (SPEC §20): gleicher Host oder Unterdomain, öffentliche Suffixe, http nie für
// https, Ports, und vor allem Phishing-Beispiele, die nie treffen dürfen.

private func match(_ entry: String, _ service: String) -> Bool {
    AutofillMatcher.matches(entryURL: entry, serviceIdentifier: service)
}

@Suite("Autofill: Treffer")
struct AutofillTrefferTests {

    @Test("Gleicher Host und Unterdomains, Gross/Klein, Schlusspunkt, Pfad egal")
    func gleicherHost() {
        #expect(match("https://example.com", "https://example.com"))
        #expect(match("https://example.com/login", "https://example.com/other?x=1"))
        #expect(match("https://example.com", "https://login.example.com/"))
        #expect(match("https://example.com", "https://a.b.c.example.com"))
        #expect(match("https://example.com", "https://www.example.com"))
        #expect(match("https://Example.COM", "https://EXAMPLE.com."))
        #expect(match("velo.example.ch", "https://velo.example.ch/anmelden"))      // ohne Schema = https
        #expect(match("https://example.com", "example.com"))                       // Domain-Kennung des Systems
        #expect(match("https://user:pw@example.com", "https://example.com"))       // Benutzerinfo zählt nicht
    }

    @Test("Umlaut-Domains: IDNA-Form und Unicode-Form sind derselbe Host")
    func idna() {
        #expect(match("https://bücher.de", "https://xn--bcher-kva.de/login"))
        #expect(match("https://xn--bcher-kva.de", "https://www.bücher.de"))
        #expect(match("https://straße.de", "https://xn--strae-oqa.de"))
    }

    @Test("http-Eintrag darf für https angeboten werden, nie umgekehrt")
    func schema() {
        #expect(match("http://intranet.example.ch", "https://intranet.example.ch"))
        #expect(match("http://intranet.example.ch", "http://intranet.example.ch"))
        #expect(!match("https://bank.example.ch", "http://bank.example.ch"))
        #expect(!match("bank.example.ch", "http://bank.example.ch"))               // ohne Schema = https
        #expect(!match("https://bank.example.ch", "ftp://bank.example.ch"))
        #expect(!match("ftp://bank.example.ch", "https://bank.example.ch"))
        #expect(!match("android://abc==@com.example.app/", "https://com.example.app"))
        #expect(!match("javascript:alert(1)", "https://example.com"))
    }

    @Test("Ports: Eintrag mit Port verlangt genau diesen, sonst nur Standardport")
    func ports() {
        #expect(match("https://nas.example.ch:5001", "https://nas.example.ch:5001/"))
        #expect(!match("https://nas.example.ch:5001", "https://nas.example.ch"))
        #expect(!match("https://nas.example.ch:5001", "https://nas.example.ch:5002"))
        #expect(!match("https://nas.example.ch", "https://nas.example.ch:8443"))
        #expect(match("https://nas.example.ch", "https://nas.example.ch:443"))
        #expect(match("https://nas.example.ch:443", "https://nas.example.ch"))
        #expect(match("http://router.example.ch", "https://router.example.ch"))   // 80 → 443 ist das Upgrade
        #expect(!match("http://router.example.ch:8080", "https://router.example.ch:8443"))
        #expect(!match("https://x.example.ch:0", "https://x.example.ch"))
        #expect(!match("https://x.example.ch", "https://x.example.ch:70000"))
    }

    @Test("IP-Adressen und einteilige Hosts nur genau")
    func ipUndEinteilig() {
        #expect(match("https://192.168.1.1", "https://192.168.1.1/admin"))
        #expect(!match("https://192.168.1.1", "https://10.192.168.1.1"))
        #expect(!match("https://1.1", "https://evil.1.1"))
        #expect(match("https://[fd00::1]:8443", "https://[fd00::1]:8443"))
        #expect(!match("https://[fd00::1]", "https://[fd00::2]"))
        #expect(match("http://localhost:8080", "http://localhost:8080"))
        #expect(!match("http://localhost", "http://evil.localhost"))
        #expect(!match("https://ch", "https://bank.ch"))
    }
}

@Suite("Autofill: Phishing und Grenzen")
struct AutofillPhishingTests {

    @Test("Phishing-Beispiele treffen nie")
    func phishing() {
        let bank = "https://beispiel-bank.example"
        for service in [
            "https://beispiel-bank.example.evil.com",            // Bankname als Unterdomain einer fremden Domain
            "https://beispiel-bank.example.evil.com/login",
            "https://evil-beispiel-bank.example",                 // gleiche Endung, anderer Name
            "https://beispielbank.example",
            "https://beispiel-bank.examp1e",
            "https://beispiel-bank.example@evil.com",             // Benutzerinfo-Trick
            "https://evil.com/beispiel-bank.example",             // Pfad-Trick
            "https://evil.com?beispiel-bank.example",
            "https://evil.com#beispiel-bank.example",
            "https://evil.com\\@beispiel-bank.example",           // Browser: Host evil.com (\ = /)
            "https://beispiel-bank.example%2F@evil.com",
            "https://example",                                     // Elternteil statt Unterdomain
            "https://xn--beispiel-bnk-ndb.example",               // Punycode-Doppelgänger (ä statt a)
        ] {
            #expect(!match(bank, service), "darf nicht treffen: \(service)")
        }
        #expect(!match("https://paypal.com", "https://paypal.com.evil.com"))
        #expect(!match("https://paypal.com", "https://evilpaypal.com"))
        #expect(!match("https://paypal.com", "https://paypal.co"))
        #expect(!match("https://login.paypal.com", "https://paypal.com"))       // nie umgekehrt
        #expect(!match("https://login.paypal.com", "https://www.paypal.com"))   // nie seitwärts
    }

    @Test("Punycode-Doppelgänger: kyrillisch, griechisch, Vollbreite")
    func doppelgaenger() {
        #expect(!match("https://apple.com", "https://аррӏе.com"))               // kyrillisch
        #expect(!match("https://apple.com", "https://xn--80ak6aa92e.com"))
        #expect(!match("https://аррӏе.com", "https://apple.com"))
        #expect(!match("https://paypal.com", "https://pаypal.com"))             // ein kyrillisches а
        #expect(!match("https://google.com", "https://gοοgle.com"))             // griechische ο
        #expect(match("https://аррӏе.com", "https://xn--80ak6aa92e.com"))       // derselbe (fremde) Host
        // Vollbreite Zeichen werden wie im Browser auf ASCII abgebildet (gleicher Host, kein Doppelgänger).
        #expect(match("https://example.com", "https://ｅｘａｍｐｌｅ.com"))
    }

    @Test("Öffentliche Suffixe: nur genau, keine Teil-Treffer über die registrierbare Domain hinaus")
    func oeffentlicheSuffixe() {
        #expect(!match("https://co.uk", "https://bank.co.uk"))
        #expect(!match("https://com.au", "https://bank.com.au"))
        #expect(!match("https://github.io", "https://evil.github.io"))
        #expect(match("https://github.io", "https://github.io"))
        #expect(match("https://alice.github.io", "https://alice.github.io/projekt"))
        #expect(match("https://alice.github.io", "https://docs.alice.github.io"))
        #expect(!match("https://alice.github.io", "https://bob.github.io"))
        #expect(match("https://bank.co.uk", "https://secure.bank.co.uk"))
        #expect(!match("https://bank.co.uk", "https://evil.co.uk"))
        #expect(!match("https://ch", "https://admin.ch"))
        #expect(AutofillMatcher.publicSuffixes.allSatisfy { $0.contains(".") && $0 == $0.lowercased() })
    }

    @Test("Ungültige Eingaben treffen nie")
    func ungueltig() {
        for bad in ["", "   ", "https://", "https:///pfad", "https://exa mple.com", "https://a..example.com",
                    "https://.example.com", "https://example.com\u{0}", "https://exa\u{202E}mple.com",
                    "https://example.com\\", "https://%65xample.com", String(repeating: "a", count: 2100) + ".com"] {
            #expect(!match(bad, "https://example.com"), "Eintrag: \(bad.prefix(40))")
            #expect(!match("https://example.com", bad), "Website: \(bad.prefix(40))")
        }
    }

    @Test("Zufallseingaben: kein Absturz, Treffer nur bei Host-Beziehung")
    func zufall() {
        let alphabet = Array("abc.-:/@\\?#%[]1 äаxn-0")
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<3000 {
            func random() -> String {
                var s = Bool.random(using: &generator) ? "https://" : ""
                for _ in 0..<Int.random(in: 0...20, using: &generator) {
                    s.append(alphabet[Int.random(in: 0..<alphabet.count, using: &generator)])
                }
                return s
            }
            let entry = random()
            let service = random()
            if match(entry, service), let e = AutofillMatcher.Origin(entry), let s = AutofillMatcher.Origin(service) {
                #expect(s.host == e.host || s.host.hasSuffix("." + e.host))
            }
        }
    }
}
