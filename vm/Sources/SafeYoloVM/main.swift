import Darwin
import Foundation
import Virtualization

// MARK: - Argument parsing

struct RunConfig {
    var kernelPath: String = ""
    var initrdPath: String = ""
    var rootfsPath: String = ""
    var cpus: Int = 2
    var memoryMB: Int = 2048
    var cmdline: String = "console=hvc0 root=/dev/vda rw quiet"
    var shares: [(hostPath: String, tag: String, readOnly: Bool)] = []
    var console: Bool = true
    var feth: String = ""            // feth interface name (e.g., "feth0")
    var fethBridgePath: String = ""  // path to feth-bridge binary
    var netSocketFD: Int32? = nil    // VM-side socket fd (set internally)
}

func printUsage() {
    let usage = """
    Usage: safeyolo-vm run [OPTIONS]

    Options:
      --kernel PATH       Path to kernel Image (required)
      --initrd PATH       Path to initramfs (required)
      --rootfs PATH       Path to root disk ext4 image (required)
      --cpus N            Number of CPUs (default: 2)
      --memory N          Memory in MB (default: 2048)
      --cmdline STRING    Kernel command line (default: console=hvc0 root=/dev/vda rw quiet)
      --share HOST:TAG:MODE  VirtioFS share (MODE = ro or rw, repeatable)
      --help              Show this help

    Example:
      safeyolo-vm run \\
        --kernel ~/.safeyolo/share/Image \\
        --initrd ~/.safeyolo/share/initramfs.cpio.gz \\
        --rootfs ~/.safeyolo/agents/test/rootfs.ext4 \\
        --cpus 4 --memory 4096 \\
        --share /Users/me/code:workspace:rw \\
        --share /tmp/config:config:ro
    """
    fputs(usage, stderr)
}

func parseArguments() -> RunConfig? {
    let args = CommandLine.arguments
    guard args.count > 1, args[1] == "run" else {
        if args.count > 1 && args[1] == "--help" {
            printUsage()
            return nil
        }
        if args.count > 1 && args[1] == "version" {
            print("safeyolo-vm 0.1.0")
            return nil
        }
        fputs("Error: expected 'run' subcommand\n", stderr)
        printUsage()
        return nil
    }

    var config = RunConfig()
    var i = 2
    while i < args.count {
        switch args[i] {
        case "--kernel":
            i += 1; guard i < args.count else { fputs("Error: --kernel requires a value\n", stderr); return nil }
            config.kernelPath = args[i]
        case "--initrd":
            i += 1; guard i < args.count else { fputs("Error: --initrd requires a value\n", stderr); return nil }
            config.initrdPath = args[i]
        case "--rootfs":
            i += 1; guard i < args.count else { fputs("Error: --rootfs requires a value\n", stderr); return nil }
            config.rootfsPath = args[i]
        case "--cpus":
            i += 1; guard i < args.count, let n = Int(args[i]), n > 0 else { fputs("Error: --cpus requires a positive integer\n", stderr); return nil }
            config.cpus = n
        case "--memory":
            i += 1; guard i < args.count, let n = Int(args[i]), n > 0 else { fputs("Error: --memory requires a positive integer\n", stderr); return nil }
            config.memoryMB = n
        case "--cmdline":
            i += 1; guard i < args.count else { fputs("Error: --cmdline requires a value\n", stderr); return nil }
            config.cmdline = args[i]
        case "--share":
            i += 1; guard i < args.count else { fputs("Error: --share requires HOST:TAG:MODE\n", stderr); return nil }
            let parts = args[i].split(separator: ":", maxSplits: 2).map(String.init)
            guard parts.count == 3, (parts[2] == "ro" || parts[2] == "rw") else {
                fputs("Error: --share format is HOST_PATH:TAG:ro|rw\n", stderr)
                return nil
            }
            config.shares.append((hostPath: parts[0], tag: parts[1], readOnly: parts[2] == "ro"))
        case "--feth":
            i += 1; guard i < args.count else { fputs("Error: --feth requires interface name\n", stderr); return nil }
            config.feth = args[i]
        case "--feth-bridge":
            i += 1; guard i < args.count else { fputs("Error: --feth-bridge requires path\n", stderr); return nil }
            config.fethBridgePath = args[i]
        case "--help":
            printUsage()
            return nil
        default:
            fputs("Error: unknown option '\(args[i])'\n", stderr)
            printUsage()
            return nil
        }
        i += 1
    }

    // Validate required args
    if config.kernelPath.isEmpty {
        fputs("Error: --kernel is required\n", stderr)
        return nil
    }
    if config.initrdPath.isEmpty {
        fputs("Error: --initrd is required\n", stderr)
        return nil
    }
    if config.rootfsPath.isEmpty {
        fputs("Error: --rootfs is required\n", stderr)
        return nil
    }

    return config
}

// MARK: - Main

guard VZVirtualMachine.isSupported else {
    fputs("Error: Virtualization is not supported on this machine\n", stderr)
    exit(1)
}

guard var config = parseArguments() else {
    exit(1)
}

do {
    // Set up feth-based networking if --feth is specified
    var fethBridgeProcess: Process?
    if !config.feth.isEmpty {
        let (vmFD, hostFD) = try VMConfiguration.createNetworkSocketPair()
        config.netSocketFD = vmFD

        // Launch feth-bridge as a child process (needs root for BPF)
        let bridgePath = config.fethBridgePath.isEmpty
            ? (ProcessInfo.processInfo.arguments[0] as NSString)
                .deletingLastPathComponent + "/feth-bridge"
            : config.fethBridgePath

        // Ensure the host fd is NOT close-on-exec
        _ = fcntl(hostFD, F_SETFD, 0)

        // Use posix_spawn to launch sudo feth-bridge.
        // sudo closes fds >= 3 by default; -C <N> closes only fds >= N.
        let closeFrom = String(hostFD + 1)
        let argv: [String] = ["sudo", "-C", closeFrom, bridgePath, String(hostFD), config.feth]
        let cArgs = argv.map { strdup($0) } + [nil]
        defer { cArgs.forEach { if let p = $0 { free(p) } } }

        var pid: pid_t = 0
        let spawnResult = posix_spawn(&pid, "/usr/bin/sudo", nil, nil, cArgs, environ)
        guard spawnResult == 0 else {
            throw VMConfigurationError.invalidConfiguration("posix_spawn failed: \(String(cString: strerror(spawnResult)))")
        }
        fputs("feth-bridge started (pid=\(pid)) on \(config.feth)\n", stderr)

        // Close our copy of the host fd — feth-bridge owns it now
        close(hostFD)
    }

    let vmConfig = try VMConfiguration.build(from: config)
    try vmConfig.validate()

    let runner = VMRunner(configuration: vmConfig)
    runner.installSignalHandlers()
    try runner.start()

    // Run until VM exits
    RunLoop.main.run()
} catch {
    fputs("Error: \(error.localizedDescription)\n", stderr)
    exit(1)
}
