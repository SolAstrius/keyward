import SwiftUI
import AppKit
import CoreGraphics

/// Places the card so the system auth sheet lands in its reserved slot.
///
/// The sheet's position is not ours to set, so it is measured instead: the card
/// appears at the last known location and then snaps the moment `coreautha`'s
/// window actually shows up. That keeps the layout correct across displays and
/// across whatever offset macOS decides to use, rather than trusting a constant.
@MainActor
final class ApprovalPanel {
    static let shared = ApprovalPanel()

    private var panel: NSPanel?
    private var poll: Timer?
    private var pending: DispatchWorkItem?
    private var ctx: PendingSignature?
    private var sheet: CGRect = ApprovalPanel.remembered

    private static let defaultsKey = "lastAuthSheetRect"

    /// Measured on this machine; replaced by the real thing on first sighting.
    private static var remembered: CGRect {
        if let s = UserDefaults.standard.string(forKey: defaultsKey) {
            let r = NSRectFromString(s)
            if r.width > 100 && r.height > 100 { return r }
        }
        let screen = CGDisplayBounds(CGMainDisplayID())
        let size = CGSize(width: 260, height: 306)
        return CGRect(x: screen.midX - size.width / 2, y: 240,
                      width: size.width, height: size.height)
    }

    /// Held back briefly on purpose.
    ///
    /// When a signature reuses a recent authentication it completes in about
    /// 20ms and no sheet ever appears — showing the card for that long is a
    /// flash of noise. The delay is still far shorter than the sheet takes to
    /// appear, so the card is never late when it does matter.
    static let showDelay: TimeInterval = 0.12

    func show(_ c: PendingSignature) {
        pending?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.ctx = c
            self.sheet = Self.remembered
            self.rebuild()
            self.startPolling()
        }
        pending = work
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.showDelay, execute: work)
    }

    func hide() {
        pending?.cancel(); pending = nil
        poll?.invalidate(); poll = nil
        panel?.orderOut(nil)
        panel = nil
        ctx = nil
    }

    // MARK: - Geometry

    private func cardRectCG(for s: CGRect) -> CGRect {
        let detail = ctx.map { CardMetrics.detailWidth(for: $0) } ?? CardMetrics.baseDetail
        let w = CardMetrics.pad + detail + CardMetrics.gap + s.width + CardMetrics.pad
        // The card grows downward for a long script; the slot stays pinned at
        // the top of its column so the sheet still lands in it.
        let content = ctx.map { ApprovalView.preferredHeight(for: $0, sheetHeight: s.height) }
                   ?? s.height
        let h = CardMetrics.pad * 2 + content
        // Keep the card on screen when a wide script pushes it leftward.
        let x = max(8, s.minX - (CardMetrics.pad + detail + CardMetrics.gap))
        return CGRect(x: x, y: s.minY - CardMetrics.pad, width: w, height: h)
    }

    private func rebuild() {
        guard let c = ctx else { return }
        let card = cardRectCG(for: sheet)

        // CGWindowList measures down from the top of the main display; AppKit
        // measures up from the bottom.
        let screenH = CGDisplayBounds(CGMainDisplayID()).height
        let origin = NSPoint(x: card.minX, y: screenH - card.maxY)

        let view = NSHostingView(rootView: ApprovalView(ctx: c, sheetSize: sheet.size))
        view.frame = NSRect(origin: .zero, size: card.size)

        if let p = panel {
            p.contentView = view
            p.setFrame(NSRect(origin: origin, size: card.size), display: true)
            return
        }

        let p = NSPanel(contentRect: NSRect(origin: origin, size: card.size),
                        styleMask: [.borderless, .nonactivatingPanel],
                        backing: .buffered, defer: false)
        p.contentView = view
        p.isOpaque = false
        p.backgroundColor = .clear
        p.hasShadow = false
        p.ignoresMouseEvents = true      // never intercept a click meant for the sheet
        p.level = NSWindow.Level(rawValue: 20)   // above windows, far below the sheet's 1000
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        p.orderFrontRegardless()
        panel = p
    }

    private func startPolling() {
        poll?.invalidate()
        var elapsed = 0.0
        let t = Timer(timeInterval: 0.05, repeats: true) { [weak self] timer in
            Task { @MainActor in
                guard let self, self.panel != nil else { timer.invalidate(); return }
                elapsed += 0.05
                if let found = Self.authSheetRect() {
                    if abs(found.minX - self.sheet.minX) > 1 || abs(found.minY - self.sheet.minY) > 1
                        || found.size != self.sheet.size {
                        self.sheet = found
                        UserDefaults.standard.set(NSStringFromRect(found), forKey: Self.defaultsKey)
                        self.rebuild()
                    }
                    timer.invalidate()
                } else if elapsed > 3.0 {
                    timer.invalidate()
                }
            }
        }
        RunLoop.main.add(t, forMode: .common)
        poll = t
    }

    /// Where the authentication sheet actually is, right now.
    private static func authSheetRect() -> CGRect? {
        let opts: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
        guard let list = CGWindowListCopyWindowInfo(opts, kCGNullWindowID) as? [[String: Any]]
        else { return nil }
        for w in list {
            let owner = (w[kCGWindowOwnerName as String] as? String ?? "").lowercased()
            guard owner.contains("coreauth") || owner.contains("securityagent")
                    || owner.contains("localauthentication") else { continue }
            guard let b = w[kCGWindowBounds as String] as? [String: Any] else { continue }
            let r = CGRect(x: b["X"] as? CGFloat ?? 0, y: b["Y"] as? CGFloat ?? 0,
                           width: b["Width"] as? CGFloat ?? 0, height: b["Height"] as? CGFloat ?? 0)
            if r.width > 150 && r.height > 150 { return r }
        }
        return nil
    }
}
