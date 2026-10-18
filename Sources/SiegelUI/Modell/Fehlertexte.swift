import Foundation
import SiegelCore

/// Deutsche Meldungen (Schweiz) für die Fehler des Kerns. Codes aus den Fehlern werden nie angezeigt.
public enum Fehlertexte {
    public static let wrongPassword = "Falsches Passwort"
    public static let kdfFailed = "Nicht genug freier Arbeitsspeicher (1 GiB nötig). Andere Programme schliessen und erneut versuchen."
    public static let newerVersion = "Diese Datei braucht eine neuere Siegel-Version"
    public static let clipboardCleared = "Zwischenablage geleert – sie enthielt dein Master-Passwort"
    /// §13.1: Ein falsches Faktor-Geheimnis ist von einem falschen Passwort nicht unterscheidbar.
    public static let wrongPasswordOrFactor = "Passwort oder ein Faktor stimmt nicht"

    public static func text(_ error: SiegelError) -> String {
        switch error {
        case .wrongPassword:
            return wrongPassword
        case let .wrongRecoveryCode(_, vaultKit):
            // Befund #19: codeKit ist mit der vaultID DIESES Tresors abgeleitet und steht bei einem fremden Code auf
            // keinem Blatt – darum nur die Kennung nennen, die der Tresor braucht.
            return wrongKit(vaultKit, shares: false)
        case .invalidRecoveryCodeFormat:
            return "Das ist kein gültiger Notfallcode. Er hat 55 Zeichen in 11 Gruppen (Ziffern und Buchstaben ausser U); unleserliche Zeichen als\u{00A0}„\u{2060}?\u{2060}“\u{00A0}eingeben, höchstens vier."
        case .recoveryCodeChecksum:
            return "Der Code enthält Fehler, die sich nicht automatisch korrigieren lassen. Prüfe jede Gruppe."
        case .recoveryConfirmationMismatch:
            return "Die Gruppen stimmen nicht mit dem Notfallkit überein. Sieh auf deinem Blatt nach."
        case let .passwordTooWeak(bits):
            return "Zu schwach (geschätzt \(Int(bits.rounded())) Bit). Nötig sind mindestens 12 Zeichen und 60 Bit."
        case .masterPasswordReused:
            return "Dieses Passwort verwendest du bereits für einen Eintrag. Wähle ein anderes."
        case .corruptFile:
            return "Die Tresordatei ist beschädigt."
        case .unsupportedVersion:
            return newerVersion + "."
        case .kdfParametersOutOfRange:
            return "Die Tresordatei enthält ungültige Parameter."
        case .kdfFailed:
            return kdfFailed
        case .vaultAlreadyExists:
            return "An diesem Ort gibt es bereits einen Tresor."
        case .vaultMissing:
            return "Die Tresordatei fehlt."
        case .vaultChangedOnDisk:
            return "Die Tresordatei wurde ausserhalb von Siegel geändert. Nichts wurde überschrieben. Bitte sperren und neu öffnen."
        case .notEnoughDiskSpace:
            return "Zu wenig freier Speicherplatz. Nichts wurde gespeichert."
        case let .csvInvalid(line, reason):
            return csv(line: line, reason: reason)
        case .exportLocationRejected:
            return "Nicht in iCloud Drive exportieren. Wähle einen Ordner auf diesem Mac."
        case let .io(code):
            return io(code)
        case let .crypto(code):
            return crypto(code)
        case let .factorMissing(kind):
            return factorMissing(kind)
        case let .factorUnavailable(kind):
            return factorUnavailable(kind)
        case .factorCancelled:
            return "Abgebrochen."
        case .wrongCard:
            return "Diese Karte gehört nicht zu diesem Tresor. Nimm die Schlüsselkarte, die du für diesen Tresor gedruckt hast."
        case .notAllowedAtLevel:
            return "In dieser Sicherheitsstufe nicht erlaubt."
        case let .totpInvalid(code):
            return totp(code)
        case let .factorTemporarilyUnavailable(kind, code):
            return factorTemporarilyUnavailable(kind, code: code)
        case .wrongSecurityKey:
            return wrongSecurityKey
        }
    }

    /// Anderer oder zurückgesetzter Sicherheitsschlüssel (v4.4, Befund hardware-3).
    public static let wrongSecurityKey =
        "Das ist nicht der Sicherheitsschlüssel dieses Tresors, oder er wurde zurückgesetzt. Stecke den Schlüssel ein, den du für Siegel registriert hast."

    /// Faktor geht gerade nicht, ist aber nicht verloren (v4.4, Befund hardware-1): erneut versuchen, kein Notfallweg.
    static func factorTemporarilyUnavailable(_ kind: FactorKind, code: String) -> String {
        switch code {
        case "se.lockout":
            return "Touch ID ist nach zu vielen Versuchen gesperrt. Entsperre den Mac einmal mit deinem Passwort – zum Beispiel Bildschirm sperren (⌃⌘Q) und wieder anmelden – und versuche es erneut."
        case "se.notReachable":
            return "Touch ID ist gerade nicht erreichbar – ist der Deckel zu? Öffne ihn oder schliesse die Tastatur mit Touch ID an und versuche es erneut."
        case "fido.busy":
            return "Der Sicherheitsschlüssel ist gerade mit einem anderen Vorgang beschäftigt. Warte kurz und versuche es erneut."
        default:
            return "Dieser Faktor geht gerade nicht. Versuche es in einem Moment erneut."
        }
    }

    /// Notfallcode mit voller Länge, der sich nicht korrigieren lässt (Befund #42): Der Kern meldet dann
    /// `invalidRecoveryCodeFormat`, weil ein Fehler im letzten Zeichen fast immer die Füllbits trifft.
    public static let recoveryCodeUncorrectable =
        "Der Code enthält Fehler, die sich nicht automatisch korrigieren lassen. Vergleiche jede Gruppe mit deinem Blatt – das letzte Zeichen ist immer 0, 8, G oder R."

    /// Meldung zu einem Notfallcode-Fehler, abhängig davon, ob die Eingabe schon vollständig ist (Befund #42).
    public static func recoveryCode(_ error: SiegelError, input: String) -> String {
        if error == .invalidRecoveryCodeFormat, VaultStore.recoveryCodeInputIsComplete(input) {
            return recoveryCodeUncorrectable
        }
        return text(error)
    }

    /// Freigabe für geschützte Einträge (neues Kit, Stufenwechsel, Export) abgebrochen oder gescheitert (§16).
    public static func protectedEntriesRelease(_ error: SiegelError) -> String {
        switch error {
        case .factorCancelled:
            return "Abgebrochen. Dafür braucht Siegel einmal deine Freigabe für die geschützten Einträge."
        case .wrongPassword:
            return "Die Freigabe für die geschützten Einträge ist gescheitert – ein Faktor stimmt nicht. Versuche es erneut."
        default:
            return text(error)
        }
    }

    /// Code bzw. Teile passen nicht zu diesem Tresor (Befund #19): kein erfundenes Blatt nennen.
    static func wrongKit(_ vaultKit: String, shares: Bool) -> String {
        let was = shares ? "Diese Teile passen" : "Dieser Code passt"
        let woher = shares ? "Sie stammen" : "Er stammt"
        return "\(was) nicht zu diesem Tresor. \(woher) von einem anderen Tresor oder einem älteren Notfallkit. Dieser Tresor braucht das Blatt mit der Kit-Kennung \(vaultKit)."
    }

    /// Ein verlangter Faktor wurde nicht mitgegeben bzw. ist für diesen Tresor nicht eingerichtet.
    static func factorMissing(_ kind: FactorKind) -> String {
        switch kind {
        case .secureEnclave: "Dafür braucht es Touch ID, es ist für diesen Tresor aber noch nicht eingerichtet."
        case .card: "Dafür braucht es die QR-Schlüsselkarte, sie ist für diesen Tresor aber noch nicht eingerichtet."
        case .securityKey: "Dafür braucht es einen Sicherheitsschlüssel, er ist für diesen Tresor aber noch nicht eingerichtet."
        }
    }

    /// Faktor auf diesem Mac nicht nutzbar (§14.1: Blob fehlt, Fingerabdrücke geändert; Kamera/Gerät fehlt). Touch ID
    /// gesperrt oder nicht erreichbar ist kein solcher Fall (`factorTemporarilyUnavailable`, v4.4).
    static func factorUnavailable(_ kind: FactorKind) -> String {
        switch kind {
        case .secureEnclave:
            "Touch ID lässt sich für diesen Tresor nicht verwenden – der Schlüssel fehlt auf diesem Mac oder die Fingerabdrücke wurden geändert. Öffne den Tresor mit dem Notfallcode."
        case .card:
            "Die Kamera ist nicht verfügbar. Tippe den Code von der Karte ab."
        case .securityKey:
            // Ein anderer bzw. zurückgesetzter Schlüssel hat eine eigene Meldung (`wrongSecurityKey`, v4.4).
            "Dieser Sicherheitsschlüssel lässt sich nicht verwenden. Er wurde abgezogen, antwortet nicht oder verlangt eine PIN-Prüfung, die Siegel nicht unterstützt."
        }
    }

    /// Meldungen für die festen reason-Codes von `CSVImport.parse` (Zeile 0 = ganze Datei).
    static func csv(line: Int, reason: String) -> String {
        let ort = line > 0 ? "Zeile \(line): " : ""
        let nichts = " Nichts wurde importiert."
        switch reason {
        case "csv.fileTooLarge":
            return "Die Datei ist grösser als 16 MiB." + nichts
        case "csv.empty":
            return "Die Datei ist leer." + nichts
        case "csv.encoding":
            return ort + "Die Datei ist nicht in UTF-8 gespeichert." + nichts
        case "csv.quote":
            return ort + "Ein Anführungszeichen steht an einer unerwarteten Stelle." + nichts
        case "csv.unterminatedQuote":
            return ort + "Ein Anführungszeichen wird bis zum Dateiende nicht geschlossen." + nichts
        case "csv.header.unknown":
            return "Das Format wurde nicht erkannt. Möglich sind Exporte aus Apple Passwörter, Chrome, Firefox und Bitwarden." + nichts
        case "csv.header.duplicate":
            return "Die Kopfzeile enthält eine Spalte doppelt." + nichts
        case "csv.fieldCount":
            return ort + "Die Anzahl Spalten passt nicht zur Kopfzeile." + nichts
        case "csv.tooManyRows":
            return "Die Datei enthält mehr als 20 000 Einträge." + nichts
        case "csv.field.title":
            return ort + "Der Titel ist zu lang (höchstens 2 KiB)." + nichts
        case "csv.field.username":
            return ort + "Der Benutzername ist zu lang (höchstens 2 KiB)." + nichts
        case "csv.field.url":
            return ort + "Die Website ist zu lang (höchstens 2 KiB)." + nichts
        case "csv.field.password":
            return ort + "Das Passwort ist zu lang (höchstens 4 KiB)." + nichts
        case "csv.field.notes":
            return ort + "Die Notizen sind zu lang (höchstens 256 KiB)." + nichts
        default:
            return ort + "Die CSV-Datei ist ungültig." + nichts
        }
    }

    /// Meldungen für die festen `.crypto`-Codes (Kern und Hardware-Modul).
    static func crypto(_ code: String) -> String {
        switch code {
        case "recovery.pendingStale":
            return "Das vorbereitete Notfallkit gilt nicht mehr, weil sich der Zugang inzwischen geändert hat. Bitte neu beginnen."
        case "factor.keyID", "factor.publicKey", "factor.length", "hw.point", "hw.blob":
            return "Der eben eingerichtete Faktor lieferte ungültige Daten. Nichts wurde geändert – bitte erneut einrichten."
        case "factor.securityKey":
            return "Der Sicherheitsschlüssel lieferte ungültige Daten. Nichts wurde geändert – bitte erneut registrieren."
        case "se.publickey":
            return "Dieser geschützte Eintrag ist beschädigt. Öffne ihn mit dem Notfallcode oder aus einer Sicherung."
        case "fido.input":
            return "Die Angaben zum Sicherheitsschlüssel in der Tresordatei sind beschädigt."
        case "se.verify":
            return "Die Prüfung mit Touch ID ergab ein anderes Ergebnis als beim Einrichten. Nichts wurde gespeichert – bitte erneut versuchen."
        case "memory.alloc":
            return "Nicht genug geschützter Arbeitsspeicher. Andere Programme schliessen und erneut versuchen."
        default:
            return "Bei der Verschlüsselung ist ein Fehler aufgetreten."
        }
    }

    /// Meldungen für die festen `totpInvalid`-Codes von `TOTP.parse` (§18).
    static func totp(_ code: String) -> String {
        let hinweis = " Erlaubt sind ein otpauth-Link (otpauth://totp/…) oder ein Base32-Geheimnis."
        switch code {
        case "totp.empty":
            return "Das 2FA-Geheimnis ist leer."
        case "totp.tooLong":
            return "Das 2FA-Geheimnis ist zu lang (höchstens 2 KiB)."
        case "totp.uri":
            return "Der otpauth-Link ist ungültig." + hinweis
        case "totp.type":
            return "Nur zeitbasierte Codes (TOTP) werden unterstützt, keine Zähler-Codes (HOTP)."
        case "totp.secret.missing":
            return "Im otpauth-Link fehlt das Geheimnis (secret=…)."
        case "totp.base32":
            return "Das Geheimnis ist kein gültiges Base32 (Buchstaben A–Z und Ziffern 2–7)."
        case "totp.secret.length":
            return "Das Geheimnis hat eine ungültige Länge (10 bis 128 Byte)."
        case "totp.algorithm":
            return "Unbekanntes Verfahren im otpauth-Link (erlaubt: SHA1, SHA256, SHA512)."
        case "totp.digits":
            return "Ungültige Anzahl Ziffern im otpauth-Link (erlaubt: 6 oder 8)."
        case "totp.period":
            return "Ungültige Periode im otpauth-Link (erlaubt: 15 bis 120 Sekunden)."
        case "totp.duplicate":
            return "Ein Parameter steht im otpauth-Link doppelt."
        case "totp.label":
            return "Aussteller oder Konto im otpauth-Link sind zu lang oder enthalten Steuerzeichen."
        default:
            return "Das 2FA-Geheimnis ist ungültig." + hinweis
        }
    }

    /// Meldungen für die festen `.io`-Codes des Kerns.
    static func io(_ code: String) -> String {
        switch code {
        case "vault.locked":
            return "Der Tresor ist gesperrt."
        case "entry.totpTooLong":
            return "Das 2FA-Geheimnis ist zu lang (höchstens 4 KiB)."
        case "entry.sealedSecrets":
            return "Die Geheimteile dieses geschützten Eintrags lassen sich nur nach dem Aufdecken ändern."
        case "entry.protection":
            return "Den Schutz dieses Eintrags kannst du nur nach dem Aufdecken ändern."
        case "entry.stale":
            return "Der Eintrag wurde inzwischen geändert. Öffne ihn neu und versuche es nochmals."
        case "export.kdbx":
            return "Die KeePass-Datei liess sich nicht erzeugen. Nichts wurde geschrieben."
        case "hw.directory", "hw.write", "hw.remove", "hw.destroy":
            return "Die Schlüsseldatei für Touch ID liess sich nicht schreiben oder entfernen."
        case "entry.notFound":
            return "Diesen Eintrag gibt es nicht mehr."
        // Selbstvernichtung (SPEC v4.3 §23)
        case "entry.destroyed":
            return "Dieser Eintrag wurde vernichtet. Seine Geheimteile sind nicht mehr lesbar – auch nicht mit dem Notfallcode."
        case "destruction.deadmanDays":
            return "Die Frist des Totmann-Schalters muss zwischen 7 und 365 Tagen liegen."
        case "destruction.maxFailedAttempts":
            return "Der Fehlversuch-Zähler muss zwischen 10 und 100 Versuchen liegen."
        case "destruction.duressPassword":
            return "Setze zuerst ein Vernichtungs-Passwort."
        case "destruction.destroyed":
            return "Entferne zuerst die vernichteten Einträge. Danach kannst du die Selbstvernichtung neu einrichten."
        case "destruction.write", "destruction.encode":
            return "Der Zustand der Selbstvernichtung liess sich nicht speichern."
        case "entry.notDeleted":
            return "Dieser Eintrag ist nicht in „Zuletzt gelöscht“."
        case "entry.titleTooLong":
            return "Der Titel ist zu lang (höchstens 2 KiB)."
        case "entry.usernameTooLong":
            return "Der Benutzername ist zu lang (höchstens 2 KiB)."
        case "entry.urlTooLong":
            return "Die Website ist zu lang (höchstens 2 KiB)."
        case "entry.passwordTooLong":
            return "Das Passwort ist zu lang (höchstens 4 KiB)."
        case "entry.notesTooLong":
            return "Die Notizen sind zu lang (höchstens 256 KiB)."
        case "save.verify":
            return "Die Prüfung nach dem Speichern ist gescheitert. Die bisherige Tresordatei ist unverändert."
        case "backup.missing":
            return "Die Sicherung wurde nicht gefunden."
        case "export.directory", "export.folder":
            return "Im gewählten Ordner lässt sich nichts anlegen. Wähle einen anderen Ordner."
        case "export.write":
            return "Die Sicherung liess sich an diesem Ort nicht schreiben. Wähle einen anderen Ort."
        case "export.verify":
            return "Die geschriebene Sicherung stimmt beim Zurücklesen nicht. Sie ist unbrauchbar – bitte erneut exportieren, am besten an einen anderen Ort."
        case "sandbox.missing":
            return "Siegel läuft nicht in seinem geschützten Bereich."
        default:
            return "Die Datei liess sich nicht lesen oder schreiben."
        }
    }
}
