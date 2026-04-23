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
    static func build(
        from config: RunConfig,
        machineIdentifier: VZGenericMachineIdentifier? = nil
    ) throws -> VZVirtualMachineConfiguration {
        // Validate file paths exist
        var requiredPaths: [(String, String)] = [
            (config.kernelPath, "kernel"),
            (config.initrdPath, "initrd"),
            (config.rootfsPath, "rootfs"),
        ]
        if !config.overlayPath.isEmpty {
            requiredPaths.append((config.overlayPath, "overlay"))
        }
        for (path, label) in requiredPaths {
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

        // Root disk (/dev/vda) and optional overlay upper (/dev/vdb).
        // Order matters: vda first, vdb second — the guest's initramfs
        // hard-codes /dev/vdb as the overlay upper when present.
        var storageDevices: [VZStorageDeviceConfiguration] = [
            try createBlockDisk(path: config.rootfsPath, readOnly: false)
        ]
        if !config.overlayPath.isEmpty {
            storageDevices.append(
                try createBlockDisk(path: config.overlayPath, readOnly: false)
            )
        }
        vmConfig.storageDevices = storageDevices

        // No virtio-net: the sandbox has no external network interface.
        // All egress goes through vsock → host UDS → proxy_bridge. This
        // is structural isolation — there's no other path out, no
        // firewall rules to misconfigure.

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

    private static func createBlockDisk(
        path: String,
        readOnly: Bool
    ) throws -> VZVirtioBlockDeviceConfiguration {
        let expanded = NSString(string: path).expandingTildeInPath
        let diskURL = URL(fileURLWithPath: expanded)

        let attachment = try VZDiskImageStorageDeviceAttachment(
            url: diskURL,
            readOnly: readOnly
        )

        return VZVirtioBlockDeviceConfiguration(attachment: attachment)
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
