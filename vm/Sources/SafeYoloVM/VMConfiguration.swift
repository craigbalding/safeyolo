import Foundation
import Virtualization

enum VMConfigurationError: LocalizedError {
    case fileNotFound(String)
    case invalidConfiguration(String)

    var errorDescription: String? {
        switch self {
        case .fileNotFound(let path):
            return "File not found: \(path)"
        case .invalidConfiguration(let reason):
            return "Invalid VM configuration: \(reason)"
        }
    }
}

struct VMConfiguration {

    /// Build a VZVirtualMachineConfiguration from RunConfig.
    ///
    /// - Parameter machineIdentifier: Optional explicit `VZGenericMachineIdentifier`.
    ///   On cold boot, pass a freshly generated identifier and persist its
    ///   `dataRepresentation` in the snapshot sidecar. On restore, decode the
    ///   sidecar's base64 identifier back into a `VZGenericMachineIdentifier`
    ///   and pass it here — VZ requires the restored VM to carry the SAME
    ///   machine identity it had at save time, or `restoreMachineStateFrom`
    ///   fails with EINVAL ("invalid argument").
    /// - Parameter macAddress: Optional explicit MAC for the virtio-net
    ///   device. Same contract as `machineIdentifier` — defaults to a new
    ///   random MAC per process, and restore fails with EINVAL unless the
    ///   same MAC is pinned back into the config.
    static func build(
        from config: RunConfig,
        machineIdentifier: VZGenericMachineIdentifier? = nil,
        macAddress: VZMACAddress? = nil
    ) throws -> VZVirtualMachineConfiguration {
        // Validate file paths exist
        for (path, label) in [
            (config.kernelPath, "kernel"),
            (config.initrdPath, "initrd"),
            (config.rootfsPath, "rootfs"),
        ] {
            let expanded = NSString(string: path).expandingTildeInPath
            guard FileManager.default.fileExists(atPath: expanded) else {
                throw VMConfigurationError.fileNotFound("\(label): \(expanded)")
            }
        }

        let vmConfig = VZVirtualMachineConfiguration()

        // CPU and memory
        let cpuCount = max(1, min(config.cpus, VZVirtualMachineConfiguration.maximumAllowedCPUCount))
        vmConfig.cpuCount = cpuCount

        let memoryBytes = UInt64(config.memoryMB) * 1024 * 1024
        let minMem = VZVirtualMachineConfiguration.minimumAllowedMemorySize
        let maxMem = VZVirtualMachineConfiguration.maximumAllowedMemorySize
        vmConfig.memorySize = max(minMem, min(memoryBytes, maxMem))

        // Platform — pin the machine identifier so save/restore works across
        // processes. Without this, VZ creates a fresh random identifier per
        // VZGenericPlatformConfiguration and restore fails with EINVAL.
        let platform = VZGenericPlatformConfiguration()
        if let identifier = machineIdentifier {
            platform.machineIdentifier = identifier
        }
        vmConfig.platform = platform

        // Boot loader
        vmConfig.bootLoader = try createBootLoader(config: config)

        // Serial console: route to a log file next to the rootfs so guest
        // kernel printk + userspace /dev/console writes are observable from
        // the host. This is our only probe channel that doesn't go through
        // virtio-net or virtiofs (both of which we've seen go silent after
        // a save/restore cycle under conditions we're still investigating).
        let rootfsExpanded = NSString(string: config.rootfsPath).expandingTildeInPath
        let consoleLogURL = URL(fileURLWithPath: rootfsExpanded)
            .deletingLastPathComponent()
            .appendingPathComponent("console.log")
        vmConfig.serialPorts = [createSerialPort(toFileAt: consoleLogURL)]

        // Root disk
        vmConfig.storageDevices = [try createRootDisk(path: config.rootfsPath)]

        // FileHandle networking (feth-based isolation)
        // The caller must have created a socketpair and passed the VM-side fd
        if let netFD = config.netSocketFD {
            vmConfig.networkDevices = [createFileHandleNetworkDevice(vmSocketFD: netFD, macAddress: macAddress)]
        }

        // VirtioFS shares
        if !config.shares.isEmpty {
            vmConfig.directorySharingDevices = config.shares.map { share in
                createFileSystemDevice(hostPath: share.hostPath, tag: share.tag, readOnly: share.readOnly)
            }
        }

        // vsock (for terminal and host-guest IPC)
        vmConfig.socketDevices = [VZVirtioSocketDeviceConfiguration()]

        // Entropy
        vmConfig.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

        // Memory balloon
        vmConfig.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]

        return vmConfig
    }

    // MARK: - Boot loader

    private static func createBootLoader(config: RunConfig) throws -> VZLinuxBootLoader {
        let kernelPath = NSString(string: config.kernelPath).expandingTildeInPath
        let kernelURL = URL(fileURLWithPath: kernelPath)

        let bootLoader = VZLinuxBootLoader(kernelURL: kernelURL)
        bootLoader.commandLine = config.cmdline

        let initrdPath = NSString(string: config.initrdPath).expandingTildeInPath
        bootLoader.initialRamdiskURL = URL(fileURLWithPath: initrdPath)

        return bootLoader
    }

    // MARK: - Serial console

    private static func createSerialPort(toFileAt url: URL) -> VZVirtioConsoleDeviceSerialPortConfiguration {
        let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()

        // Create / truncate the log file — fresh per run so it only shows
        // this invocation's guest output. Append would mix runs together
        // and defeat the purpose of the probe.
        FileManager.default.createFile(atPath: url.path, contents: nil)
        guard let fh = FileHandle(forWritingAtPath: url.path) else {
            // Fall back to /dev/null so we don't fail the VM boot over a
            // log-file hiccup; we'll just not have console output visible.
            let devNull = FileHandle(forWritingAtPath: "/dev/null")!
            serialPort.attachment = VZFileHandleSerialPortAttachment(
                fileHandleForReading: nil,
                fileHandleForWriting: devNull
            )
            return serialPort
        }
        serialPort.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: nil,
            fileHandleForWriting: fh
        )
        return serialPort
    }

    // MARK: - Root disk

    private static func createRootDisk(path: String) throws -> VZVirtioBlockDeviceConfiguration {
        let expanded = NSString(string: path).expandingTildeInPath
        let diskURL = URL(fileURLWithPath: expanded)

        let attachment = try VZDiskImageStorageDeviceAttachment(
            url: diskURL,
            readOnly: false
        )

        return VZVirtioBlockDeviceConfiguration(attachment: attachment)
    }

    // MARK: - FileHandle networking (feth-based isolation)

    /// Create a network device backed by a Unix datagram socket.
    /// The VM sends/receives raw Ethernet frames on the socket.
    /// The other end of the socketpair goes to feth-bridge for forwarding to a feth interface.
    ///
    /// - Parameter macAddress: Optional explicit MAC. Must match what was
    ///   in effect at save time, otherwise VZ rejects the restore.
    static func createFileHandleNetworkDevice(
        vmSocketFD: Int32,
        macAddress: VZMACAddress? = nil
    ) -> VZVirtioNetworkDeviceConfiguration {
        let networkDevice = VZVirtioNetworkDeviceConfiguration()
        let fileHandle = FileHandle(fileDescriptor: vmSocketFD, closeOnDealloc: true)
        networkDevice.attachment = VZFileHandleNetworkDeviceAttachment(fileHandle: fileHandle)
        if let mac = macAddress {
            networkDevice.macAddress = mac
        }
        return networkDevice
    }

    /// Create a Unix datagram socketpair for VM networking.
    /// Returns (vmFD, hostFD) — vmFD goes to the VM, hostFD goes to feth-bridge.
    static func createNetworkSocketPair() throws -> (Int32, Int32) {
        var fds: [Int32] = [0, 0]
        let ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard ret == 0 else {
            throw VMConfigurationError.invalidConfiguration("socketpair failed: \(String(cString: strerror(errno)))")
        }

        // Tune socket buffers (per Lima/vfkit best practices)
        var sndbuf: Int32 = 1 * 1024 * 1024  // 1MB send
        var rcvbuf: Int32 = 4 * 1024 * 1024  // 4MB receive
        setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &rcvbuf, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &sndbuf, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &rcvbuf, socklen_t(MemoryLayout<Int32>.size))

        return (fds[0], fds[1])
    }

    // MARK: - VirtioFS directory sharing

    private static func createFileSystemDevice(
        hostPath: String,
        tag: String,
        readOnly: Bool
    ) -> VZVirtioFileSystemDeviceConfiguration {
        let expanded = NSString(string: hostPath).expandingTildeInPath
        let directoryURL = URL(fileURLWithPath: expanded, isDirectory: true)

        let sharedDirectory = VZSharedDirectory(url: directoryURL, readOnly: readOnly)
        let singleShare = VZSingleDirectoryShare(directory: sharedDirectory)

        let device = VZVirtioFileSystemDeviceConfiguration(tag: tag)
        device.share = singleShare

        return device
    }
}
