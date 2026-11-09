import Darwin
import Foundation

/// An owned loopback endpoint that refuses traffic before native Tor exists.
/// The app retains this for its entire lifetime, including after switching ports.
final class RefusingTorProxy {
    let port: UInt16
    private let descriptor: Int32

    init() throws {
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        guard listener >= 0 else { throw Self.failure() }
        var retained = false
        defer { if !retained { Darwin.close(listener) } }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        address.sin_port = 0
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, listen(listener, 16) == 0 else { throw Self.failure() }
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(listener, $0, &size)
            }
        }
        guard named == 0, address.sin_port != 0 else { throw Self.failure() }
        port = UInt16(bigEndian: address.sin_port)
        descriptor = listener
        retained = true
        DispatchQueue(label: "epix-unavailable-tor").async {
            while true {
                let connection = accept(listener, nil, nil)
                if connection >= 0 {
                    Darwin.close(connection)
                } else if errno != EINTR {
                    // Keep ownership on transient accept errors. Never expose a
                    // port that the browser still uses to an unrelated process.
                    Thread.sleep(forTimeInterval: 0.1)
                }
            }
        }
    }

    private static func failure() -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: nil)
    }
}
