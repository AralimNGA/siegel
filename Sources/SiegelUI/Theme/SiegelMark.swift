import SwiftUI

/// Bildmarke «Schlüssel-S» von Siegel als SwiftUI-Shape.
///
/// Dieselbe Geometrie wie `design/logo.svg` (Quelle der Wahrheit: `design/bauen.py`):
/// Scheibe Ø 21 u, senkrecht geteilt 5 · 3 · 5 · 3 · 5, zwei Schlitze (3 u) mit Schlüssellochköpfen
/// (Ø 6 u) bei (−2.5 u, −4 u) und (+2.5 u, +4 u). Oben läuft der Schlitz nach rechts aus, unten nach
/// links; das verbleibende Schwarz ist ein S. Ein einziger geschlossener Umriss ohne Löcher.
///
/// Die Scheibe füllt das grösste zentrierte Quadrat in `rect` (wie `Circle`). Scharf auf ganzen Pixeln
/// wird die Marke, wenn die Scheibe ein Vielfaches von 21 pt misst (u = 1 pt, 2 pt, 4 pt …) und der
/// Rahmen auf ganzen Punkten liegt, z. B. `.frame(width: 84, height: 84)` im Sperrbildschirm.
///
/// `riegel` (0 = Ruhe, 1 = offen) schiebt beide Schlüssellöcher um bis zu 3 u Richtung Mündung:
/// die Riegel gleiten aus dem Siegel. Animierbar, z. B.
/// `withAnimation(.easeOut(duration: 0.18)) { riegel = 1 }`.
public struct SiegelMark: Shape {
    public var riegel: CGFloat

    public init(riegel: CGFloat = 0) {
        self.riegel = riegel
    }

    public var animatableData: CGFloat {
        get { riegel }
        set { riegel = newValue }
    }

    // MASS-ANFANG (von design/bauen.py geschrieben, nicht von Hand ändern)
    static let r: CGFloat = 10.5        // Scheibenradius in u
    static let schlitz: CGFloat = 3     // Schlitzbreite in u
    static let ky: CGFloat = 4          // Schlitzachse bei y = ∓ky
    static let rk: CGFloat = 3          // Radius Schlüssellochkopf
    static let kx: CGFloat = 2.5        // Kopfmitte bei x = ∓kx
    static let hub: CGFloat = 3         // Riegelweg bei riegel = 1
    // MASS-ENDE

    public func path(in rect: CGRect) -> Path {
        let seite = min(rect.width, rect.height)
        guard seite > 0 else { return Path() }
        let u = seite / (2 * Self.r)
        let mitte = CGPoint(x: rect.midX, y: rect.midY)
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: mitte.x + x * u, y: mitte.y + y * u)
        }

        let r = Self.r, rk = Self.rk, ky = Self.ky, h = Self.schlitz / 2
        let t = min(max(riegel, -0.5), 1.5)              // Überschwingen erlaubt, Geometrie bleibt gültig
        let hx = -Self.kx + Self.hub * t                  // Kopfmitte des oberen Schlüssellochs (x)

        // Oberes Schlüsselloch in Einheiten u, y nach unten. Das untere ist dasselbe, um 180° gedreht.
        let yo = -(ky + h), yu = -(ky - h)                // Ober- und Unterkante des Schlitzes
        let xMuendungO = (r * r - yo * yo).squareRoot()   // Austritt der Oberkante am Rand (spitzes S-Ende)
        let xMuendungU = (r * r - yu * yu).squareRoot()
        let xHals = hx + (rk * rk - h * h).squareRoot()  // Ansatz des Schlitzes am Kopf
        let phi = asin(h / rk)                            // Halswinkel am Kopf (30°)

        let aO = atan2(yo, xMuendungO)                    // Randwinkel der Mündungen
        let aU = atan2(yu, xMuendungU)
        let oben = -CGFloat.pi / 2

        var pfad = Path()
        pfad.move(to: p(0, -r))
        // Rand von oben bis zur oberen Mündung (im Uhrzeigersinn)
        pfad.addRelativeArc(center: mitte, radius: r * u, startAngle: .radians(oben), delta: .radians(aO - oben))
        for drehung in [CGFloat(1), -1] {
            let s = drehung                               // −1: um 180° gedreht (unteres Schlüsselloch)
            pfad.addLine(to: p(s * xHals, s * yo))
            // Kopf auf dem langen Weg umrunden (gegen den Uhrzeigersinn)
            pfad.addRelativeArc(center: p(s * hx, s * -ky), radius: rk * u,
                                startAngle: .radians(-phi + (s < 0 ? .pi : 0)),
                                delta: .radians(-(2 * .pi - 2 * phi)))
            pfad.addLine(to: p(s * xMuendungU, s * yu))
            // Rand bis zur nächsten Mündung bzw. zurück nach oben
            let start = aU + (s < 0 ? .pi : 0)
            let ende = s > 0 ? aO + .pi : oben + 2 * .pi
            pfad.addRelativeArc(center: mitte, radius: r * u, startAngle: .radians(start), delta: .radians(ende - start))
        }
        pfad.closeSubpath()
        return pfad
    }
}
