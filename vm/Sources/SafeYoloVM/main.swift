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
    var noTerminal: Bool = false     // detach mode: skip vsock terminal, keep VM alive
    var snapshotOnSignal: String = "" // path to write snapshot to on SIGUSR1
    var restoreFrom: String = ""      // path to snapshot file to restore from
}

let helperVersion = "0.2.0"

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
      --feth IFACE        feth interface for network isolation
      --feth-bridge PATH  Path to feth-bridge binary
      --no-terminal       Detach mode: skip vsock terminal, keep VM alive for SSH
      --snapshot-on-signal PATH
                          Write a VM snapshot to PATH when SIGUSR1 is received.
                          Sidecar metadata is written to PATH.meta.json.
      --restore-from PATH Restore VM from a previously-saved snapshot at PATH
                          instead of cold-booting. Must pass the same
                          --kernel / --initrd / --memory / --cpus values that
                          were used when the snapshot was created.
      --help              Show this help

    Example:
      safeyolo-vm run \\
        --kernel ~/.safeyolo/share/Image \\
        --initrd ~/.safeyolo/share/initramfs.cpio.gz \\
        --rootfs ~/.safeyolo/agents/test/rootfs.ext4 \\
        --cpus 4 --memory 4096 \\
        --share /Users/me/code:workspace:rw \\
        --feth feth0
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
            print("safeyolo-vm \(helperVersion)")
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
        case "--no-terminal":
            config.noTerminal = true
        case "--snapshot-on-signal":
            i += 1; guard i < args.count else { fputs("Error: --snapshot-on-signal requires a path\n", stderr); return nil }
            config.snapshotOnSignal = args[i]
        case "--restore-from":
            i += 1; guard i < args.count else { fputs("Error: --restore-from requires a path\n", stderr); return nil }
            config.restoreFrom = args[i]
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
    if !config.feth.isEmpty {
        // Network isolation via feth pair.
        // Create socketpair: VM gets one end, feth-bridge gets the other.
        // Use posix_spawn_file_actions to dup the host fd into fd 3 of the
        // child process, avoiding the sudo fd-closing problem.
        let (vmFD, hostFD) = try VMConfiguration.createNetworkSocketPair()
        config.netSocketFD = vmFD

        let bridgePath = config.fethBridgePath.isEmpty
            ? (ProcessInfo.processInfo.arguments[0] as NSString)
                .deletingLastPathComponent + "/feth-bridge"
            : config.fethBridgePath

        // Ensure the host fd is NOT close-on-exec so the child inherits it
        _ = fcntl(hostFD, F_SETFD, 0)

        // Launch feth-bridge directly (no sudo — BPF is group-accessible
        // via access_bpf on macOS with Wireshark/OrbStack installed)
        let argv: [String] = [bridgePath, String(hostFD), config.feth]
        let cArgs = argv.map { strdup($0) } + [nil]
        defer { cArgs.forEach { if let p = $0 { free(p) } } }

        var pid: pid_t = 0
        let rc = posix_spawn(&pid, bridgePath, nil, nil, cArgs, environ)
        guard rc == 0 else {
            throw VMConfigurationError.invalidConfiguration("posix_spawn feth-bridge: \(String(cString: strerror(rc)))")
        }
        close(hostFD)  // Parent no longer needs it
    }

    let vmConfig = try VMConfiguration.build(from: config)
    try vmConfig.validate()

    let vmQueue = DispatchQueue(label: "com.safeyolo.vm", qos: .userInteractive)
    let vm = VZVirtualMachine(configuration: vmConfig, queue: vmQueue)
    let runner = VMRunner(vm: vm, queue: vmQueue)

    // Compute the hardware fingerprint we'll need for save (sidecar) and
    // restore (sidecar validation). Done once here so a SIGUSR1 mid-run
    // doesn't have to recompute kernel/initrd hashes.
    let fingerprint = VMSnapshot.Fingerprint(
        memoryMB: config.memoryMB,
        cpus: config.cpus,
        kernelSHA256: try VMSnapshot.sha256(ofFileAt: config.kernelPath),
        initrdSHA256: try VMSnapshot.sha256(ofFileAt: config.initrdPath),
        vmHelperVersion: helperVersion
    )

    if !config.snapshotOnSignal.isEmpty {
        let url = URL(fileURLWithPath: NSString(string: config.snapshotOnSignal).expandingTildeInPath)
        runner.configureSnapshotOnSignal(url: url, fingerprint: fingerprint)
    }

    runner.installSignalHandlers()

    let isRestoring = !config.restoreFrom.isEmpty
    if isRestoring {
        let url = URL(fileURLWithPath: NSString(string: config.restoreFrom).expandingTildeInPath)
        try runner.restoreFromSnapshot(url: url, expectedFingerprint: fingerprint)
    } else {
        try runner.start()
    }

    // In detach mode (--no-terminal), the VM stays alive until SIGTERM and
    // is accessed via SSH (`safeyolo agent shell <name>`); no vsock-term.
    // Otherwise, attach the vsock terminal once the guest's per-run init
    // has spawned it.
    if !config.noTerminal {
        let terminal = VSockTerminal(vm: vm, queue: vmQueue)

        DispatchQueue.global().async {
            // Retry vsock connection until guest is ready (up to 120s for first boot with npm install).
            // On restore, sshd + per-run init are nearly instant — skip the
            // first 2s sleep so the terminal attaches as fast as possible.
            //
            // Only break on terminal states (.stopped / .error), NOT on
            // transient .pausing/.paused/.saving/.restoring/.resuming —
            // those happen mid-snapshot and the VM will be back to .running
            // momentarily.
            var connected = false
            for attempt in 1...60 {
                if !(isRestoring && attempt == 1) {
                    sleep(2)
                }
                if vm.state == .stopped || vm.state == .error { break }

                if vm.state == .running && terminal.tryConnect() {
                    connected = true
                    break
                }
            }

            if connected {
                terminal.run()
            }
            // Terminal session ended — stop VM
            runner.requestStopFromMain()
        }
    }

    // Park the main thread on libdispatch's main queue. This drains the
    // signal-handling DispatchSources (SIGINT/SIGTERM/SIGUSR1) reliably
    // for command-line tools — RunLoop.main.run() leaves the main queue
    // unserviced when no other dispatch work is scheduled, which broke
    // SIGUSR1 in --no-terminal mode (signal arrived, default action
    // killed the process before the dispatch source fired).
    //
    // dispatchMain() never returns; the VM-state observer's exitClean()
    // calls exit() to terminate.
    dispatchMain()
} catch {
    fputs("Error: \(error.localizedDescription)\n", stderr)
    // Use sysexits.h EX_TEMPFAIL (75) for snapshot-related errors so the CLI
    // can detect this case and fall back to cold-boot capture cleanly.
    if error is VMSnapshot.Error {
        exit(75)
    }
    exit(1)
}
