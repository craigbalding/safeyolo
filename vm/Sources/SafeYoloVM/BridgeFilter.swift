import Foundation

/// Enable pf IP filtering on a macOS bridge interface.
///
/// Apple's bridge interfaces have IP filtering disabled by default,
/// which means pf rules on the bridge are ignored. This uses the
/// BRDGSFILT ioctl to enable the IFBF_FILT_USEIPF flag, allowing
/// pf to intercept packets traversing the bridge.
///
/// Requires root privileges (run via sudo).
enum BridgeFilter {

    // From bsd/net/if_bridgevar.h in XNU kernel source
    private static let BRDGSFILT: UInt = 24
    private static let IFBF_FILT_USEIPF: UInt32 = 0x00000001

    // From sys/ioctl.h — SIOCSDRVSPEC
    // SIOCSDRVSPEC = _IOW('i', 124, struct ifdrv)
    // = IOC_IN(0x80000000) | (sizeof(ifdrv)=40=0x28 << 16) | ('i'=0x69 << 8) | 124=0x7C
    // = 0x8028697C
    private static let SIOCSDRVSPEC: UInt = 0x8028697C

    /// Layout must match struct ifdrv from <net/if_var.h>
    /// struct ifdrv {
    ///     char    ifd_name[IFNAMSIZ];  // 16 bytes
    ///     unsigned long ifd_cmd;        // 8 bytes (64-bit)
    ///     size_t  ifd_len;              // 8 bytes
    ///     void   *ifd_data;             // 8 bytes
    /// };
    struct ifdrv {
        var ifd_name: (CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                       CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar) = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        var ifd_cmd: UInt = 0
        var ifd_len: UInt = 0
        var ifd_data: UnsafeMutableRawPointer? = nil
    }

    struct ifbrparam {
        var ifbrp_filter: UInt32 = 0
    }

    static func enableIPFilter(on bridge: String) -> Bool {
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        guard sock >= 0 else {
            fputs("Error: cannot create socket: \(String(cString: strerror(errno)))\n", stderr)
            return false
        }
        defer { close(sock) }

        var param = ifbrparam(ifbrp_filter: IFBF_FILT_USEIPF)
        var drv = ifdrv()
        drv.ifd_cmd = BRDGSFILT
        drv.ifd_len = UInt(MemoryLayout<ifbrparam>.size)

        // Copy bridge name into ifd_name tuple
        withUnsafeMutablePointer(to: &drv.ifd_name) { namePtr in
            let raw = UnsafeMutableRawPointer(namePtr).assumingMemoryBound(to: CChar.self)
            bridge.utf8CString.withUnsafeBufferPointer { buf in
                let len = min(buf.count, 16)
                for i in 0..<len {
                    raw[i] = buf[i]
                }
            }
        }

        // Point ifd_data at our param struct
        let result = withUnsafeMutablePointer(to: &param) { paramPtr -> Int32 in
            drv.ifd_data = UnsafeMutableRawPointer(paramPtr)
            return withUnsafeMutablePointer(to: &drv) { drvPtr -> Int32 in
                ioctl(sock, UInt(SIOCSDRVSPEC), drvPtr)
            }
        }

        if result < 0 {
            fputs("Error: ioctl BRDGSFILT on \(bridge): \(String(cString: strerror(errno)))\n", stderr)
            return false
        }

        fputs("ipfilter enabled on \(bridge)\n", stderr)
        return true
    }
}
