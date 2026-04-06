import Foundation
import Virtualization

/// Manages the lifecycle of a VZVirtualMachine: start, state observation, signal handling, shutdown.
class VMRunner: NSObject {

    let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private var observation: NSKeyValueObservation?
    private var hasExited = false

    init(vm: VZVirtualMachine, queue: DispatchQueue? = nil) {
        self.vm = vm
        self.queue = queue ?? DispatchQueue(label: "com.safeyolo.vm.runner", qos: .userInteractive)
        super.init()
        observeState()
    }

    // MARK: - State observation

    private func observeState() {
        observation = vm.observe(\.state, options: [.new]) { [weak self] vm, _ in
            self?.handleStateChange(vm.state)
        }
    }

    private func handleStateChange(_ state: VZVirtualMachine.State) {
        switch state {
        case .stopped:
            exitClean(code: 0)
        case .error:
            fputs("Error: VM entered error state\n", stderr)
            exitClean(code: 1)
        case .running:
            break
        case .starting:
            break
        case .stopping:
            fputs("VM stopping...\n", stderr)
        case .pausing, .paused, .resuming, .saving, .restoring:
            break
        @unknown default:
            break
        }
    }

    // MARK: - Start (completion handler API, not async)

    func start() throws {
        let semaphore = DispatchSemaphore(value: 0)
        var startError: Error?

        // Terminal raw mode is handled by VSockTerminal, not here.

        queue.async { [self] in
            vm.start { (result: Result<Void, Error>) in
                if case .failure(let error) = result {
                    startError = error
                }
                semaphore.signal()
            }
        }

        semaphore.wait()
        if let error = startError {
            restoreTerminal()
            throw error
        }
    }

    // MARK: - Shutdown

    /// Called from outside (e.g., when vsock terminal session ends).
    func requestStopFromMain() {
        requestStop()
    }

    /// Graceful shutdown: sends ACPI power button request to guest.
    private func requestStop() {
        queue.async { [self] in
            guard vm.canRequestStop else {
                fputs("Cannot request graceful stop, forcing...\n", stderr)
                forceStop()
                return
            }

            do {
                try vm.requestStop()
            } catch {
                fputs("Graceful stop failed: \(error.localizedDescription), forcing...\n", stderr)
                forceStop()
            }
        }

        // If the VM doesn't stop within 5 seconds, force it
        DispatchQueue.global().asyncAfter(deadline: .now() + 5.0) { [self] in
            if !hasExited {
                fputs("VM did not stop within 5s, forcing...\n", stderr)
                forceStop()
            }
        }
    }

    /// Force stop using completion handler API (not the async variant).
    private func forceStop() {
        queue.async { [self] in
            guard vm.state == .running || vm.state == .starting || vm.state == .stopping else {
                exitClean(code: 1)
                return
            }
            // Use stop(completionHandler:) — the callback API, not the async stop()
            vm.stop { [self] (error: Error?) in
                if let error = error {
                    fputs("Force stop failed: \(error.localizedDescription)\n", stderr)
                }
                exitClean(code: 1)
            }
        }
    }

    private func exitClean(code: Int32) {
        guard !hasExited else { return }
        hasExited = true
        restoreTerminal()
        exit(code)
    }

    // MARK: - Signal handling

    func installSignalHandlers() {
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)

        // First Ctrl-C: try graceful stop. Second Ctrl-C: force stop immediately.
        let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigintSource.setEventHandler { [weak self] in
            guard let self = self else { return }
            if self.stopRequested {
                fputs("\nForce stopping VM...\n", stderr)
                self.forceStop()
            } else {
                fputs("\nShutting down VM... (Ctrl-C again to force)\n", stderr)
                self.stopRequested = true
                self.requestStop()
            }
        }
        sigintSource.resume()

        let sigtermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        sigtermSource.setEventHandler { [weak self] in
            fputs("Received SIGTERM, shutting down VM...\n", stderr)
            self?.requestStop()
        }
        sigtermSource.resume()

        _signalSources = [sigintSource, sigtermSource]
    }

    private var _signalSources: [Any] = []
    private var stopRequested = false

    // MARK: - Terminal raw mode

    private var originalTermios: termios?

    private func enableRawMode() {
        guard isatty(STDIN_FILENO) != 0 else { return }

        var raw = termios()
        tcgetattr(STDIN_FILENO, &raw)
        originalTermios = raw

        // Keep ISIG enabled so Ctrl-C generates SIGINT for our signal handler.
        // Disable ICANON (line buffering) and ECHO (character echo) for raw serial passthrough.
        raw.c_lflag &= ~tcflag_t(ICANON | ECHO)
        raw.c_iflag &= ~tcflag_t(IXON | ICRNL)
        withUnsafeMutablePointer(to: &raw.c_cc) { ptr in
            let cc = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: cc_t.self)
            cc[Int(VMIN)] = 1
            cc[Int(VTIME)] = 0
        }

        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw)
    }

    private func restoreTerminal() {
        guard var original = originalTermios else { return }
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original)
        originalTermios = nil
    }
}
