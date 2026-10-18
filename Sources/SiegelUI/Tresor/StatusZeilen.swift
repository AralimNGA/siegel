import SiegelCore
import SwiftUI

/// Statuszeilen unten in der Seitenleiste (SPEC §1.5, §4, §7.4, §7.9):
/// - „Notfallkit nicht bestätigt – jetzt einrichten“ (nicht wegklickbar)
/// - „Exportdatei endgültig löschen“ nach einem CSV-Export (bis erledigt oder weggeklickt)
/// - dezent „Keine Sicherung ausserhalb dieses Macs“ mit „Sicherung exportieren…“
/// - dezent „Zweiter Sicherungsort nicht verbunden“, wenn dort Änderungen fehlen (Befund #8/#14)
public struct VaultStatusLines: View {
    let model: AppModel

    public init(model: AppModel) {
        self.model = model
    }

    private var editing: Bool { model.browser.mode == .edit }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // §23.2: nach einer Vernichtung (nur echte Sitzung), bis „Entfernen“.
            if let banner = model.destructionBanner {
                DestructionBannerView(model: model, banner: banner)
            }
            if model.needsRecoveryKitConfirmation {
                kitLine
            }
            if model.exportedCSV != nil {
                exportLine
            }
            if model.showsExternalBackupHint {
                backupLine
            }
            if model.showsSecondaryBackupWarning {
                secondaryLine
            }
        }
    }

    private var secondaryLine: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(model.secondaryBackupUnreachable ? "Zweiter Sicherungsort nicht verbunden" : "Zweiter Sicherungsort: Schreiben fehlgeschlagen")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
            Text(secondaryDetail)
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        }
        .padding(.horizontal, 2)
        .padding(.top, 2)
        .accessibilityElement(children: .combine)
    }

    private var secondaryDetail: String {
        let name = model.secondaryBackupName.map { "„" + $0 + "“" } ?? "Ordner"
        guard let letzte = model.settings.lastSecondaryBackupAt else { return name + " · noch keine Sicherung dort" }
        return name + " · letzte Sicherung dort am " + Anzeige.tag(letzte)
    }

    private var kitLine: some View {
        Button {
            model.startNewRecoveryKit()
        } label: {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: "exclamationmark.circle")
                    .font(.system(size: 12, weight: .medium))
                Text(Typo.keepCompounds("Notfallkit nicht bestätigt – jetzt einrichten"))
                    .font(Theme.caption.weight(.medium))
                    .fixedSize(horizontal: false, vertical: true)
                    .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .semibold))
            }
            .foregroundStyle(Theme.text)
            .padding(.horizontal, 10)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Theme.text, lineWidth: 1)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(editing)
        .accessibilityLabel("Notfallkit nicht bestätigt, jetzt einrichten")
    }

    private var exportLine: some View {
        HStack(spacing: 8) {
            Button {
                model.deleteExportedCSV()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "trash")
                        .font(.system(size: 11))
                    Text("Exportdatei endgültig löschen")
                        .font(Theme.caption.weight(.medium))
                        .lineLimit(1)
                        .minimumScaleFactor(0.85)
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Die CSV-Exportdatei mit allen Passwörtern im Klartext liegt noch auf diesem Mac.")
            Button {
                model.dismissExportedCSVLine()
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 9, weight: .semibold))
                    .frame(width: 18, height: 18)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(Theme.secondary)
            .help("Zeile ausblenden")
            .accessibilityLabel("Zeile ausblenden")
        }
        .foregroundStyle(Theme.text)
        .padding(.leading, 10)
        .padding(.trailing, 6)
        .frame(height: 34)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
        )
    }

    private var backupLine: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text("Keine Sicherung ausserhalb dieses Macs")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.9)
            Button("Sicherung exportieren…") { model.request(.backupExport) }
                .buttonStyle(QuietButtonStyle(font: Theme.caption.weight(.semibold)))
                .disabled(editing)
        }
        .padding(.horizontal, 2)
        .padding(.top, 2)
    }
}
