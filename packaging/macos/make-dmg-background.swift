import AppKit

let W: CGFloat = 600, H: CGFloat = 400
let logoPath = CommandLine.arguments[1]
let outPath = CommandLine.arguments[2]

func hex(_ s: String, _ a: CGFloat = 1) -> NSColor {
    var v: UInt64 = 0; Scanner(string: s).scanHexInt64(&v)
    return NSColor(srgbRed: CGFloat((v>>16)&0xff)/255, green: CGFloat((v>>8)&0xff)/255, blue: CGFloat(v&0xff)/255, alpha: a)
}

func drawContent() {
    // background gradient (near-black, subtle)
    let bg = NSGradient(colors: [hex("14141C"), hex("09090A")])!
    bg.draw(in: NSRect(x: 0, y: 0, width: W, height: H), angle: -90)

    // logo, top-center (transparent PNG composited on the gradient)
    if let logo = NSImage(contentsOfFile: logoPath) {
        let lw: CGFloat = 104, lh = lw * (logo.size.height / max(logo.size.width, 1))
        logo.draw(in: NSRect(x: (W-lw)/2, y: H-28-lh, width: lw, height: lh))
    }

    // instruction under the icon row
    let para = NSMutableParagraphStyle(); para.alignment = .center
    let instr = "Drag EpixNet onto the Applications folder to install"
    instr.draw(in: NSRect(x: 0, y: 48, width: W, height: 22), withAttributes: [
        .font: NSFont.systemFont(ofSize: 15, weight: .medium),
        .foregroundColor: hex("C9CBD4"), .paragraphStyle: para,
    ])

    // arrow between the two icons (icon centers sit at Finder y=190 -> AppKit y=210),
    // built as one filled shape (shaft + head) so a gradient fills the whole thing
    let y: CGFloat = 210, x0: CGFloat = 244, x1: CGFloat = 356
    let arrow = NSBezierPath(roundedRect: NSRect(x: x0, y: y-4, width: (x1-14)-x0, height: 8), xRadius: 4, yRadius: 4)
    let head = NSBezierPath()
    head.move(to: NSPoint(x: x1+8, y: y)); head.line(to: NSPoint(x: x1-16, y: y+15)); head.line(to: NSPoint(x: x1-16, y: y-15)); head.close()
    arrow.append(head)
    NSGraphicsContext.saveGraphicsState()
    arrow.addClip()
    NSGradient(colors: [hex("31BDC6"), hex("8A4BDB")])!.draw(in: NSRect(x: x0, y: y-15, width: (x1+8)-x0, height: 30), angle: 0)
    NSGraphicsContext.restoreGraphicsState()
}

func rep(scale: CGFloat) -> NSBitmapImageRep {
    let r = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(W*scale), pixelsHigh: Int(H*scale),
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    r.size = NSSize(width: W, height: H)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: r)
    drawContent()
    NSGraphicsContext.restoreGraphicsState()
    return r
}

let img = NSImage(size: NSSize(width: W, height: H))
img.addRepresentation(rep(scale: 1))
img.addRepresentation(rep(scale: 2))
try! img.tiffRepresentation(using: .lzw, factor: 0)!.write(to: URL(fileURLWithPath: outPath))
print("wrote \(outPath)")
