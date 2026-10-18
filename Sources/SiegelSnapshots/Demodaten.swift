import Foundation
import SiegelCore

/// Erfundene Einträge für Snapshots (keine echten Firmen, Personen oder Passwörter; Domains auf .example).
enum Demodaten {
    static let masterPassword = "kiesel-wolke-tanne-faden-lampe-ufer"
    static let passphrase = "kiesel-wolke-tanne-faden-lampe-ufer"
    /// Fester Generator-Wert für reproduzierbare Bilder (beginnt nicht mit = + - @).
    static let generated = "q7R!vN2#kLm9$wXz4@Tb8&Hc"

    static func datum(_ text: String) -> Date {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "Europe/Zurich")
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        return formatter.date(from: text) ?? Date(timeIntervalSince1970: 1_790_000_000)
    }

    static func entries() -> [VaultEntry] {
        var bank = VaultEntry(title: "Beispiel Bank", username: "lena.muster", password: "vT7#qLm2!xR9pZc4sWd8",
                              url: "https://ebanking.beispiel-bank.example",
                              notes: "Vertragsnummer 1048-22\nKarte: Debit, endet auf 0000\nSicherheitsfrage: erstes Velo")
        bank.history = [
            PasswordHistoryItem(password: "Kx4!pQ8mZr2wN6tB", changed: datum("2026-08-14 09:12")),
            PasswordHistoryItem(password: "sommerweg-17-alt", changed: datum("2026-03-02 18:40")),
        ]
        var mail = VaultEntry(title: "Muster-Mail", username: "lena.muster@muster-mail.example",
                              password: "Hq4$mW8zKp2nVb6x", url: "https://mail.muster-mail.example")
        mail.history = [PasswordHistoryItem(password: "Lm3#rT9vQx2k", changed: datum("2026-05-20 07:55"))]
        return [
            bank,
            mail,
            VaultEntry(title: "Velo-Shop", username: "lena.m", password: "brise-kanal-ofen-netz",
                       url: "www.velo-shop.example"),
            VaultEntry(title: "Bibliothek Seeland", username: "S-204511", password: "Rk9!fT3w",
                       url: "https://katalog.bibliothek-seeland.example"),
            VaultEntry(title: "Stromversorger Nord", username: "kunde-77120", password: "Z8m#Lq2vR4xN",
                       url: "https://portal.strom-nord.example"),
            VaultEntry(title: "WLAN Zuhause", username: "", password: "lindenblatt-im-herbst-42",
                       notes: "Netzname: Muster-5G"),
            VaultEntry(title: "Krankenkasse Beispiel", username: "KK-88412", password: "Tz6&wP3nLq9s",
                       url: "https://meine.krankenkasse-beispiel.example"),
            VaultEntry(title: "Bergbahnen Pass", username: "lena.muster@example.ch", password: "gipfel-nebel-ski-24",
                       url: "https://shop.bergbahnen-beispiel.example"),
            VaultEntry(title: "Steuern Kanton", username: "ST-4471-09", password: "Pv8!kR2mXw5z",
                       url: "https://etax.kanton-beispiel.example"),
            VaultEntry(title: "Musikschule Aare", username: "eltern.muster", password: "Cello-Dur-7!",
                       url: "https://portal.musikschule-aare.example"),
            VaultEntry(title: "Wolkenspeicher", username: "lena@wolke.example", password: "Nb5$xQ7wLr2pK9vT",
                       url: "https://wolke.example",
                       notes: "2FA: Authenticator-App\nWiederherstellungscodes im Notfallkit-Ordner"),
            // Gleich wie das Master-Passwort (Hinweis in der Detailansicht)
            VaultEntry(title: "Velo-Forum", username: "lena_m", password: masterPassword,
                       url: "https://forum.velo-beispiel.example"),
            // Gemischte Schriften im Host: „а“ ist kyrillisch → Anzeige als Punycode
            VaultEntry(title: "Paket-Dienst", username: "lena.muster", password: "Wq3!zL8nRt6v",
                       url: "https://p\u{0430}ket-dienst.example/login"),
        ]
    }

    /// Später gelöscht (für „Zuletzt gelöscht“).
    static func deletedEntries() -> [VaultEntry] {
        [
            VaultEntry(title: "Altes Handy-Abo", username: "0790000000", password: "Abo-2019-alt!",
                       url: "https://kundenkonto.mobil-beispiel.example"),
            VaultEntry(title: "Kino-Club", username: "lena.muster", password: "popcorn-reihe-9",
                       url: "https://kino-club.example"),
        ]
    }

    /// CSV-Export im Format von Apple Passwörter (wird über den echten `CSVImport.parse` gelesen):
    /// 6 Einträge, davon 1 Dublette (Bibliothek), 1 Konflikt (Velo-Shop), 1 mit 2FA-Geheimnis, 1 mit
    /// führendem Apostroph im Passwort (typischer Tabellenprogramm-Rest).
    static let csvApple = """
        Title,URL,Username,Password,Notes,OTPAuth\r
        Fotodienst,https://foto.example,lena.muster,Fq2!xL9m,,\r
        Velo-Shop,https://www.velo-shop.example,lena.m,anderes-passwort-1,,\r
        Bibliothek Seeland,https://katalog.bibliothek-seeland.example,S-204511,Rk9!fT3w,,\r
        Zeitung Online,https://abo.zeitung.example,lena@example.ch,Zt5#mQ8w,,otpauth://totp/Beispiel?secret=JBSWY3DPEHPK3PXP\r
        Turnverein,https://tv-beispiel.example,lmuster,'Tv-2026-sprung,"Mitgliedschaft: Aktiv",\r
        Reisebüro,https://reisen.example,lena.muster,Rb4$kN7x,,\r

        """
}
