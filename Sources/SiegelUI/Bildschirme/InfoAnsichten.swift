import AppKit
import SiegelCore
import SwiftUI

// Einstellungen → Automatisches Ausfüllen (SPEC v4 §20, ehrlicher Stand) und Info → Lizenzen (Befund #44:
// ISC und MIT verlangen den Hinweis in allen Kopien der Software; Inhalt nach LIZENZEN.md).

/// Automatisches Ausfüllen: was vorbereitet ist, was fehlt, nach welchen Regeln Siegel ausfüllen würde.
struct AutofillPage: View {
    let model: AppModel

    var body: some View {
        SettingsForm(title: "Automatisches Ausfüllen",
                     text: "Siegel kann Passwörter in Safari und anderen Apps ausfüllen – vorbereitet, aber auf diesem Mac nicht aktiv.",
                     width: 560) {
            InfoBlock(title: "Stand", symbol: "info.circle") {
                Bullet("Die Erweiterung liegt im Projekt bei (Erweiterungen/SiegelAutofill). Gebaut wird sie nur mit einem bezahlten Apple-Entwicklerkonto: Das kostenlose Konto bekommt die nötige Berechtigung nicht (gemessen).")
                Bullet("Mit dem echten System ungetestet. Bis das geprüft ist, gilt sie als Vorschau.")
                Bullet(model.policy.autofillAllowed
                       ? "Die Stufe \(model.level.title) erlaubt das Ausfüllen."
                       : "In Stufe \(model.level.title) füllt Siegel nie automatisch aus – die Erweiterung sagt dann „nur in der App“.")
            }
            InfoBlock(title: "Regeln", symbol: "checklist") {
                Bullet("Nur bei derselben Website oder einer Unterdomain davon – keine Teil-Treffer über die Domain hinaus (öffentliche Endungen wie co.uk werden erkannt).")
                Bullet("Nie ein https-Eintrag für eine http-Seite.")
                Bullet("Nie für Einträge mit Schutz 3, 4 oder 5.")
            }
            .padding(.top, 6)
            InfoBlock(title: "Einrichten (mit bezahltem Konto)", symbol: "hammer") {
                Bullet("1. Team-ID aus dem bezahlten Apple-Entwicklerkonto bereithalten.")
                Bullet("2. Im Projektordner bauen:")
                Text("SIEGEL_TEAM_ID=<Team-ID> skripte/autofill_bauen.sh")
                    .font(Theme.mono(12))
                    .foregroundStyle(Theme.text)
                    .padding(.leading, 14)
                    .padding(.vertical, 2)
                Bullet("3. Siegel neu starten, in den Systemeinstellungen unter „Allgemein“ das automatische Ausfüllen öffnen und Siegel einschalten.")
            }
            .padding(.top, 6)
        }
    }
}

/// Info → Lizenzen: Drittkomponenten in der App und ihre Lizenztexte (unverändert).
struct LicensesPage: View {
    let model: AppModel

    var body: some View {
        SettingsForm(title: "Lizenzen",
                     text: "Siegel enthält Werke anderer. Ihre Lizenzen verlangen diese Hinweise in jeder Kopie.",
                     width: 560) {
            VStack(spacing: 0) {
                Hairline()
                ForEach(LicenseTexts.components, id: \.name) { teil in
                    HStack(alignment: .firstTextBaseline, spacing: 14) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(teil.name).font(Theme.bodyMedium)
                            Text(teil.detail)
                                .font(Theme.caption)
                                .foregroundStyle(Theme.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 12)
                        Text(teil.license)
                            .font(Theme.caption.weight(.medium))
                    }
                    .padding(.vertical, 10)
                    Hairline()
                }
            }
            LicenseText(title: "libsodium 1.0.22 – ISC-Lizenz", text: LicenseTexts.isc)
                .padding(.top, 14)
            LicenseText(title: "zxcvbn 4.4.2 – MIT-Lizenz", text: LicenseTexts.mit)
                .padding(.top, 10)
            Text(Typo.keepCompounds(LicenseTexts.dataNote))
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .lineSpacing(2)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 6)
        }
    }
}

/// Abschnitt mit Titel und Symbol (Autofill-Seite).
struct InfoBlock<Content: View>: View {
    var title: String
    var symbol: String
    var content: Content

    init(title: String, symbol: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.symbol = symbol
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                Image(systemName: symbol)
                    .font(.system(size: 12, weight: .medium))
                    .frame(width: 16)
                Text(title)
                    .font(Theme.bodyMedium)
            }
            VStack(alignment: .leading, spacing: 6) { content }
                .padding(.leading, 24)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Aufzählungszeile.
struct Bullet: View {
    var text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(Typo.keepCompounds(text))
            .font(Theme.caption)
            .foregroundStyle(Theme.text)
            .lineSpacing(2)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// Lizenztext in SF Mono mit Rahmen (Text auswählbar).
struct LicenseText: View {
    var title: String
    var text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(Theme.caption.weight(.semibold))
            Text(text)
                .font(Theme.mono(10.5))
                .foregroundStyle(Theme.text)
                .lineSpacing(1)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }
}

/// Inhalt der Lizenzseite (nach LIZENZEN.md; die Lizenztexte unverändert).
enum LicenseTexts {
    struct Component {
        let name: String
        let detail: String
        let license: String
    }

    static let components: [Component] = [
        Component(name: "libsodium 1.0.22", detail: "Verschlüsselung, Argon2id, sicherer Speicher – statisch in der App",
                  license: "ISC"),
        Component(name: "zxcvbn 4.4.2", detail: "Schätz-Algorithmus (nach Swift übertragen) und Häufigkeitslisten",
                  license: "MIT"),
        Component(name: "Webster's Second International (web2)",
                  detail: "Englische Wortliste aus macOS, Wörterbuch von 1934", license: "gemeinfrei"),
        Component(name: "Apple-Frameworks und Swift", detail: "SwiftUI, AppKit, CryptoKit u. a. – Teil von macOS, nicht mitgeliefert",
                  license: "macOS"),
    ]

    static let isc = """
        ISC License

        Copyright (c) 2013-2026
        Frank Denis <j at pureftpd dot org>

        Permission to use, copy, modify, and/or distribute this software for any
        purpose with or without fee is hereby granted, provided that the above
        copyright notice and this permission notice appear in all copies.

        THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
        WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
        MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
        ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
        WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
        ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
        OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
        """

    static let mit = """
        Copyright (c) 2016 Rian Hunter
        Copyright (c) 2012-2016 Dan Wheeler and Dropbox, Inc.

        Permission is hereby granted, free of charge, to any person obtaining
        a copy of this software and associated documentation files (the
        "Software"), to deal in the Software without restriction, including
        without limitation the rights to use, copy, modify, merge, publish,
        distribute, sublicense, and/or sell copies of the Software, and to
        permit persons to whom the Software is furnished to do so, subject to
        the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
        LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
        OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
        WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
        """

    static let dataNote = "Die Häufigkeitslisten von zxcvbn beruhen auf Wortzählungen der englischen Wikipedia, Film- und TV-Untertiteln (über Wiktionary), Namen der US-Volkszählung und einer öffentlichen Passwortsammlung. Siegel nutzt nur die Reihenfolge der Wörter. Die Wortliste web2 (Webster's Second International, 1934) ist gemeinfrei. Die Auswahl öffentlicher Domain-Endungen (z. B. co.uk) für das automatische Ausfüllen folgt der Public Suffix List von Mozilla (MPL 2.0)."

    /// Version aus dem App-Bundle („1.0 (1)“); ohne Bündel (Entwicklung) „Entwicklung“.
    static var version: String {
        let info = Bundle.main.infoDictionary
        guard let kurz = info?["CFBundleShortVersionString"] as? String else { return "Entwicklung" }
        let bau = info?["CFBundleVersion"] as? String
        return bau.map { kurz + " (" + $0 + ")" } ?? kurz
    }
}
