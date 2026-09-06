import SwiftUI
import AppKit

/// Context for one pending signature, sent by the daemon.
struct PendingSignature: Codable {
    var headline: String
    var app: String?
    var appBundle: String?
    var process: String?
    var key: String?
    var fingerprint: String?
    var host: String?
    var repo: String?
    var branch: String?
    var subject: String?
    var command: String?
    var chain: [String]
    var session: String?
}

enum CardMetrics {
    static let pad: CGFloat = 24
    static let detailWidth: CGFloat = 470
    static let gap: CGFloat = 20
}

/// The card the system Touch ID sheet docks into.
///
/// The sheet belongs to `coreautha`, sits at window layer 1000, and cannot be
/// restyled, reparented or moved — so instead of fighting it, the card is laid
/// out *around* it: details on the left, and a reserved slot on the right of
/// exactly the sheet's dimensions. The panel finds the sheet's real frame at
/// runtime and positions itself so the sheet lands in that slot.
struct ApprovalView: View {
    let ctx: PendingSignature
    let sheetSize: CGSize

    var body: some View {
        HStack(spacing: CardMetrics.gap) {
            details
                .frame(width: CardMetrics.detailWidth, alignment: .leading)
            // The slot. Empty on purpose — the system draws into it.
            Color.clear
                .frame(width: sheetSize.width, height: sheetSize.height)
        }
        .padding(CardMetrics.pad)
        .background(
            ZStack {
                VisualEffect(material: .hudWindow)
                Color.black.opacity(0.55)
            }
            .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .strokeBorder(.white.opacity(0.13), lineWidth: 1)
            )
            .shadow(color: .black.opacity(0.55), radius: 40, y: 16)
        )
        .preferredColorScheme(.dark)
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 11) {
                if let b = ctx.appBundle, let icon = iconFor(b) {
                    Image(nsImage: icon).resizable().frame(width: 34, height: 34)
                }
                Text(ctx.headline)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(.white)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .padding(.bottom, 14)

            // Grouped, with a rule between groups: what is being done, who
            // asked, and which key. Label-above-value gives each value the full
            // width, which is what lets the font be readable at all.
            ForEach(Array(groups.enumerated()), id: \.offset) { idx, group in
                if idx > 0 {
                    Divider().overlay(.white.opacity(0.10))
                        .padding(.vertical, 11)
                }
                VStack(alignment: .leading, spacing: 9) {
                    ForEach(group, id: \.label) { block($0) }
                }
            }
        }
        .frame(height: sheetSize.height, alignment: .center)
    }

    private struct Field: Hashable {
        let label: String
        let value: String
        var mono: Bool = true
        var lines: Int = 1
    }

    /// Three groups, five values at most. Everything else — fingerprint, raw
    /// session id, the untrimmed process chain — lives in the app window, where
    /// there is room to read it.
    private var groups: [[Field]] {
        var act: [Field] = []
        if let s = ctx.subject { act.append(Field(label: "Commit", value: s, mono: false, lines: 2)) }
        if let c = ctx.command { act.append(Field(label: "Command", value: c, lines: 2)) }
        if let h = ctx.host { act.append(Field(label: "Server", value: h)) }
        if let r = ctx.repo, ctx.host == nil { act.append(Field(label: "Repository", value: r)) }

        var who: [Field] = []
        who.append(Field(label: "Requested by", value: requestedBy, mono: false, lines: 2))
        if let v = shortChain { who.append(Field(label: "Via", value: v)) }

        var key: [Field] = []
        if let k = ctx.key { key.append(Field(label: "Key", value: k)) }

        return [act, who, key].filter { !$0.isEmpty }
    }

    private var requestedBy: String {
        let app = ctx.app ?? ctx.process ?? "an unknown process"
        if let s = ctx.session { return "\(app) — \(s)" }
        return app
    }

    /// Collapses repeats and the app's own launch helpers, which say nothing.
    private var shortChain: String? {
        var seen: [String] = []
        for name in ctx.chain {
            let n = name.lowercased()
            if n == ctx.app?.lowercased() || n == "disclaimer" { continue }
            if seen.last?.lowercased() == n { continue }
            seen.append(name)
        }
        if seen.count > 4 {
            seen = [seen.first!, "…"] + seen.suffix(2)
        }
        return seen.isEmpty ? nil : seen.joined(separator: " › ")
    }

    private func block(_ f: Field) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(f.label.uppercased())
                .font(.system(size: 9.5, weight: .semibold))
                .tracking(0.7)
                .foregroundStyle(.white.opacity(0.40))
            Text(f.value)
                .font(f.mono ? .system(size: 13, design: .monospaced)
                             : .system(size: 13.5))
                .foregroundStyle(.white)
                .lineLimit(f.lines)
                .truncationMode(.middle)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var provenance: String? {
        var parts: [String] = []
        if let a = ctx.app { parts.append(a) }
        if let p = ctx.process, p != ctx.app { parts.append(p) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private func iconFor(_ bundle: String) -> NSImage? {
        FileManager.default.fileExists(atPath: bundle)
            ? NSWorkspace.shared.icon(forFile: bundle) : nil
    }
}

/// The same blur the system dialogs are built from.
struct VisualEffect: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    func makeNSView(context: Context) -> NSVisualEffectView {
        let v = NSVisualEffectView()
        v.material = material
        v.blendingMode = .behindWindow
        v.state = .active
        return v
    }
    func updateNSView(_ v: NSVisualEffectView, context: Context) { v.material = material }
}
