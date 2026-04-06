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
    static func build(from config: RunConfig) throws -> VZVirtualMachineConfiguration {
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

        // Boot loader
        vmConfig.bootLoader = try createBootLoader(config: config)

        // Serial console (stdin/stdout)
        vmConfig.serialPorts = [createSerialPort()]

        // Root disk
        vmConfig.storageDevices = [try createRootDisk(path: config.rootfsPath)]

        // NAT networking
        vmConfig.networkDevices = [createNetworkDevice()]

        // VirtioFS shares
        if !config.shares.isEmpty {
            vmConfig.directorySharingDevices = config.shares.map { share in
                createFileSystemDevice(hostPath: share.hostPath, tag: share.tag, readOnly: share.readOnly)
            }
        }

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

    private static func createSerialPort() -> VZVirtioConsoleDeviceSerialPortConfiguration {
        let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()

        let inputHandle = FileHandle.standardInput
        let outputHandle = FileHandle.standardOutput

        let attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: inputHandle,
            fileHandleForWriting: outputHandle
        )
        serialPort.attachment = attachment

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

    // MARK: - NAT networking

    private static func createNetworkDevice() -> VZVirtioNetworkDeviceConfiguration {
        let networkDevice = VZVirtioNetworkDeviceConfiguration()
        networkDevice.attachment = VZNATNetworkDeviceAttachment()
        return networkDevice
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
