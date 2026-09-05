import AppKit
import CoreGraphics
import Foundation

// Keyward's mark: a keyhole inside a ward. The concentric arcs beneath read as
// both a fingerprint and a shield's layers — the two things the app is about.

func squircle(_ r: CGRect, _ radius: CGFloat) -> CGPath {
    CGPath(roundedRect: r, cornerWidth: radius, cornerHeight: radius, transform: nil)
}

func draw(size S: CGFloat) -> CGImage {
    let cs = CGColorSpaceCreateDeviceRGB()
    let ctx = CGContext(data: nil, width: Int(S), height: Int(S), bitsPerComponent: 8,
                        bytesPerRow: 0, space: cs,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.setAllowsAntialiasing(true)
    ctx.interpolationQuality = .high

    // macOS app icons sit inset in their canvas rather than bleeding to the edge.
    let inset = S * 0.085
    let box = CGRect(x: inset, y: inset, width: S - inset * 2, height: S - inset * 2)
    let path = squircle(box, box.width * 0.2237)

    ctx.saveGState()
    ctx.addPath(path)
    ctx.clip()
    let grad = CGGradient(colorsSpace: cs, colors: [
        CGColor(red: 0.36, green: 0.30, blue: 0.86, alpha: 1),
        CGColor(red: 0.16, green: 0.13, blue: 0.42, alpha: 1),
        CGColor(red: 0.07, green: 0.06, blue: 0.20, alpha: 1),
    ] as CFArray, locations: [0, 0.55, 1])!
    ctx.drawLinearGradient(grad, start: CGPoint(x: box.minX, y: box.maxY),
                           end: CGPoint(x: box.maxX, y: box.minY), options: [])

    // A soft light source behind the keyhole lifts it off the gradient.
    let glow = CGGradient(colorsSpace: cs, colors: [
        CGColor(red: 0.75, green: 0.72, blue: 1.0, alpha: 0.42),
        CGColor(red: 0.75, green: 0.72, blue: 1.0, alpha: 0.0),
    ] as CFArray, locations: [0, 1])!
    let c = CGPoint(x: box.midX, y: box.midY + box.height * 0.06)
    ctx.drawRadialGradient(glow, startCenter: c, startRadius: 0,
                           endCenter: c, endRadius: box.width * 0.42, options: [])
    ctx.restoreGState()

    // A single ward ring: structure that still reads at 16px, where concentric
    // arcs turn to mush and start looking like a wifi glyph.
    ctx.saveGState()
    ctx.addPath(path)
    ctx.clip()
    ctx.setLineWidth(box.width * 0.028)
    ctx.setStrokeColor(CGColor(red: 0.84, green: 0.82, blue: 1.0, alpha: 0.34))
    ctx.addArc(center: c, radius: box.width * 0.315,
               startAngle: 0, endAngle: .pi * 2, clockwise: false)
    ctx.strokePath()
    ctx.restoreGState()

    // The keyhole: bowl and stem filled separately. As one path they cancel —
    // the circle and the rectangle wind in opposite directions, so the nonzero
    // rule punches a notch out of the join.
    let bowlR = box.width * 0.125
    let bowlC = CGPoint(x: box.midX, y: box.midY + box.height * 0.075)
    let stemTop = bowlC.y
    let stemBot = box.midY - box.height * 0.185
    let halfTop = bowlR * 0.42
    let halfBot = bowlR * 0.78

    let ink = CGColor(red: 0.97, green: 0.96, blue: 1.0, alpha: 1)
    ctx.setFillColor(ink)

    ctx.beginPath()
    ctx.addArc(center: bowlC, radius: bowlR, startAngle: 0, endAngle: .pi * 2, clockwise: false)
    ctx.fillPath()

    let stem = CGMutablePath()
    stem.move(to: CGPoint(x: bowlC.x - halfTop, y: stemTop))
    stem.addLine(to: CGPoint(x: bowlC.x + halfTop, y: stemTop))
    stem.addLine(to: CGPoint(x: bowlC.x + halfBot, y: stemBot))
    stem.addLine(to: CGPoint(x: bowlC.x - halfBot, y: stemBot))
    stem.closeSubpath()
    ctx.addPath(stem)
    ctx.fillPath()

    // A hairline edge keeps the squircle crisp against a light desktop.
    ctx.addPath(path)
    ctx.setLineWidth(max(1, S * 0.004))
    ctx.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.10))
    ctx.strokePath()

    return ctx.makeImage()!
}

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "./Keyward.iconset"
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)
for (px, name) in [(16,"16x16"),(32,"16x16@2x"),(32,"32x32"),(64,"32x32@2x"),
                   (128,"128x128"),(256,"128x128@2x"),(256,"256x256"),(512,"256x256@2x"),
                   (512,"512x512"),(1024,"512x512@2x")] {
    let img = draw(size: CGFloat(px))
    let url = URL(fileURLWithPath: "\(out)/icon_\(name).png")
    let rep = NSBitmapImageRep(cgImage: img)
    try! rep.representation(using: .png, properties: [:])!.write(to: url)
}
print("wrote \(out)")
