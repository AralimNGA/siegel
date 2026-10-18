import AppKit
import Foundation
import SiegelCore
import Testing
@testable import SiegelAutofillErweiterung

/// Zwischenablage für Tests: zählt nur, hat keinen Inhalt.
@MainActor
final class TestAblage: AutofillZwischenablage {
    var changeCount: Int
    private(set) var geleert = 0

    init(changeCount: Int) {
        self.changeCount = changeCount
    }

    func leeren() {
        geleert += 1
        changeCount += 1   // wie NSPasteboard.clearContents
    }
}

/// Abläufe der Autofill-Erweiterung ohne System: keine echte Zwischenablage, kein Tresor, kein Touch-ID-Dialog
/// (Befunde bau-1 bis bau-3).
@MainActor
@Suite("Autofill-Erweiterung")
struct AutofillErweiterungTests {
    static func treffer(_ anzahl: Int) -> [AutofillTreffer] {
        (0..<anzahl).map {
            AutofillTreffer(id: UUID(), title: "Konto \($0)", username: "lena.muster", protection: .fingerabdruck)
        }
    }

    static func controller(_ ablage: TestAblage, ereignis: NSEvent? = nil) -> CredentialProviderViewController {
        let vc = CredentialProviderViewController()
        vc.zwischenablage = ablage
        vc.aktuellesEreignis = { ereignis }
        _ = vc.view
        return vc
    }

    /// Text ins Passwortfeld setzen, wie es der Feld-Editor tut (danach controlTextDidChange).
    static func eingeben(_ vc: CredentialProviderViewController, _ text: String) {
        vc.passwortFeld.stringValue = text
        vc.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: vc.passwortFeld))
    }

    static func taste(_ zeichen: String, _ flags: NSEvent.ModifierFlags = []) -> NSEvent? {
        NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: flags, timestamp: 0, windowNumber: 0,
                         context: nil, characters: zeichen, charactersIgnoringModifiers: zeichen, isARepeat: false,
                         keyCode: 9)
    }

    // MARK: bau-2: eingefügtes Master-Passwort

    @Test func eingefuegtesPasswortWirdNachEntsperrenGeleert() {
        let ablage = TestAblage(changeCount: 41)
        let vc = Self.controller(ablage)   // kein Ereignis = Menü „Einfügen“
        Self.eingeben(vc, "Kupfer-Lawine-7-Brot")
        vc.nachEntsperren(.success(Self.treffer(2)))
        #expect(ablage.geleert == 1)
        #expect(vc.zustand == .liste)
        #expect(vc.meldung.stringValue == CredentialProviderViewController.zwischenablageGeleert)
        #expect(!vc.meldung.isHidden)
        // Ein zweites Aufräumen fasst sie nicht noch einmal an.
        vc.viewWillDisappear()
        #expect(ablage.geleert == 1)
    }

    @Test func einfuegenMitBefehlstasteZaehlt() {
        let ablage = TestAblage(changeCount: 5)
        let vc = Self.controller(ablage, ereignis: Self.taste("v", .command))
        Self.eingeben(vc, "Kupfer-Lawine-7-Brot")
        vc.nachEntsperren(.success([]))
        #expect(ablage.geleert == 1)
        #expect(vc.zustand == .hinweis)
        #expect(vc.meldung.stringValue.hasPrefix(CredentialProviderViewController.zwischenablageGeleert + " Keine passenden"))
    }

    @Test func veraenderteZwischenablageBleibtUnangetastet() {
        let ablage = TestAblage(changeCount: 41)
        let vc = Self.controller(ablage)
        Self.eingeben(vc, "Kupfer-Lawine-7-Brot")
        ablage.changeCount += 1   // inzwischen etwas anderes kopiert
        vc.nachEntsperren(.success(Self.treffer(2)))
        #expect(ablage.geleert == 0)
        #expect(vc.meldung.isHidden)
    }

    @Test func getipptesPasswortLaesstZwischenablageInRuhe() {
        let ablage = TestAblage(changeCount: 41)
        let vc = Self.controller(ablage, ereignis: Self.taste("k"))
        var text = ""
        for zeichen in "Kupfer" {
            text.append(zeichen)
            Self.eingeben(vc, text)
        }
        vc.nachEntsperren(.success(Self.treffer(1)))
        vc.viewWillDisappear()
        #expect(ablage.geleert == 0)
    }

    @Test func abbruchLeertAuch() {
        let ablage = TestAblage(changeCount: 41)
        let vc = Self.controller(ablage)
        Self.eingeben(vc, "Kupfer-Lawine-7-Brot")
        vc.viewWillDisappear()   // Abbrechen, Frist, Auswahl: alle über aufraeumen()
        #expect(ablage.geleert == 1)
        #expect(vc.passwortFeld.stringValue.isEmpty)
    }

    @Test func falschesPasswortBehaeltDenMerker() {
        let ablage = TestAblage(changeCount: 41)
        let vc = Self.controller(ablage)
        Self.eingeben(vc, "Kupfer-Lawine-7-Brod")
        vc.nachEntsperren(.failure(SiegelError.wrongPassword))
        #expect(ablage.geleert == 0)
        #expect(vc.zustand == .passwort)
        vc.nachEntsperren(.success(Self.treffer(1)))
        #expect(ablage.geleert == 1)
    }

    // MARK: bau-3: Meldung nach gescheiterter Auswahl

    @Test func abgebrochenesTouchIDBleibtSichtbar() {
        let vc = Self.controller(TestAblage(changeCount: 0))
        vc.treffer = Self.treffer(3)
        vc.auswahlGescheitert(SiegelError.factorCancelled)
        #expect(vc.zustand == .liste)
        #expect(vc.meldung.stringValue == "Touch ID abgebrochen.")
        #expect(!vc.meldung.isHidden)
    }

    @Test func meldungUndAnzahlStehenBeide() {
        let vc = Self.controller(TestAblage(changeCount: 0))
        vc.treffer = Self.treffer(12)
        vc.auswahlGescheitert(SiegelError.factorCancelled)
        #expect(vc.meldung.stringValue == "Touch ID abgebrochen. 12 Einträge passen, gezeigt werden die ersten 8.")
        vc.auswahlGescheitert(SiegelError.wrongPassword)
        #expect(vc.meldung.stringValue == "Falsches Passwort. 12 Einträge passen, gezeigt werden die ersten 8.")
    }

    // MARK: bau-1: Touch ID vorübergehend nicht verfügbar

    static let gesperrt = SiegelError.factorTemporarilyUnavailable(.secureEnclave, "se.lockout")
    static let unerreichbar = SiegelError.factorTemporarilyUnavailable(.secureEnclave, "se.notReachable")

    @Test func vorruebergehendIstNichtEndgueltig() {
        for fehler in [Self.gesperrt, Self.unerreichbar, .factorCancelled, .wrongPassword, .kdfFailed] {
            #expect(!CredentialProviderViewController.istEndgueltig(fehler))
        }
        let endgueltig: [any Error] = [SiegelError.factorUnavailable(.secureEnclave), SiegelError.corruptFile("x"),
                                       AutofillHinweis.rollback]
        for fehler in endgueltig {
            #expect(CredentialProviderViewController.istEndgueltig(fehler))
        }
    }

    @Test func vorruebergehendNenntKeinenNotfallweg() {
        let sperre = CredentialProviderViewController.text(Self.gesperrt, kopf: nil)
        let deckel = CredentialProviderViewController.text(Self.unerreichbar, kopf: nil)
        for text in [sperre, deckel] {
            #expect(!text.contains("Notfall"))
            #expect(!text.contains("Fingerabdrücke"))
            #expect(text.contains("erneut"))
        }
        #expect(sperre.contains("Passwort"))
        #expect(deckel.contains("Deckel") && deckel.contains("Tastatur"))
        let verloren = CredentialProviderViewController.text(SiegelError.factorUnavailable(.secureEnclave), kopf: nil)
        #expect(verloren.contains("Notfallcode"))
    }

    @Test func sperreBeimEntsperrenFuehrtZurueckZumPasswort() {
        let vc = Self.controller(TestAblage(changeCount: 0))
        vc.nachEntsperren(.failure(Self.gesperrt))
        #expect(vc.zustand == .passwort)
        #expect(vc.meldung.stringValue == CredentialProviderViewController.text(Self.gesperrt, kopf: nil))
        vc.nachEntsperren(.failure(SiegelError.factorUnavailable(.secureEnclave)))
        #expect(vc.zustand == .hinweis)
    }

    @Test func sperreBeimAufdeckenFuehrtZurueckZurListe() {
        let vc = Self.controller(TestAblage(changeCount: 0))
        vc.treffer = Self.treffer(2)
        vc.auswahlGescheitert(Self.unerreichbar)
        #expect(vc.zustand == .liste)
        #expect(vc.meldung.stringValue == CredentialProviderViewController.text(Self.unerreichbar, kopf: nil))
        vc.auswahlGescheitert(SiegelError.factorUnavailable(.secureEnclave))
        #expect(vc.zustand == .hinweis)
    }

    @Test func verbindeSetztPunkte() {
        typealias C = CredentialProviderViewController
        #expect(C.verbinde(nil, nil) == "")
        #expect(C.verbinde("a.", nil, "") == "a.")
        #expect(C.verbinde("Falsches Passwort", "Weiter.") == "Falsches Passwort. Weiter.")
        #expect(C.verbinde("Touch ID abgebrochen.", "Weiter.") == "Touch ID abgebrochen. Weiter.")
        #expect(C.verbinde("Ohne Punkt") == "Ohne Punkt")
    }
}
