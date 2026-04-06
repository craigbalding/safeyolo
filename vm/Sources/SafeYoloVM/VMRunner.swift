import Foundation
import Virtualization

/// Manages the lifecycle of a VZVirtualMachine: start, state observation, signal handling, shutdown.
class VMRunner: NSObject {

    private let vm: VZVirtualMachine
    private let queue = DispatchQueue(label: "com.safeyolo.vm", qos: .userInteractive)
    private var observation: NSKeyValueObservation?
    private var hasExited = false

    init(configuration: VZVirtualMachineConfiguration) {
        self.vm = VZVirtualMachine(configuration: configuration, queue: queue)
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
            fputs("VM stopped\n", stderr)
            exitClean(code: 0)
        case .error:
            fputs("VM entered error state\n", stderr)
            exitClean(code: 1)
        case .running:
            fputs("VM running\n", stderr)
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

    // MARK: - Start

    func start() throws {
        let semaphore = DispatchSemaphore(value: 0)
        var startError: Error?

        // Put terminal in raw mode for serial console passthrough
        enableRawMode()

        queue.async { [self] in
            vm.start { result in
                switch result {
                case .success:
                    break
                case .failure(let error):
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

    private func forceStop() {
        queue.async { [self] in
            if vm.state == .running || vm.state == .starting {
                Task {
                    do {
                        try await vm.stop()
                    } catch {
                        fputs("Force stop failed: \(error.localizedDescription)\n", stderr)
                    }
                    exitClean(code: 1)
                }
                return
            }
            exitClean(code: 1)
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
        // Ignore default signal handling so DispatchSource can catch them
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)

        let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigintSource.setEventHandler { [weak self] in
            fputs("\nReceived SIGINT, shutting down VM...\n", stderr)
            self?.requestStop()
        }
        sigintSource.resume()

        let sigtermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        sigtermSource.setEventHandler { [weak self] in
            fputs("Received SIGTERM, shutting down VM...\n", stderr)
            self?.requestStop()
        }
        sigtermSource.resume()

        // Keep sources alive
        _signalSources = [sigintSource, sigtermSource]
    }

    private var _signalSources: [Any] = []

    // MARK: - Terminal raw mode

    private var originalTermios: termios?

    private func enableRawMode() {
        guard isatty(STDIN_FILENO) != 0 else { return }

        var raw = termios()
        tcgetattr(STDIN_FILENO, &raw)
        originalTermios = raw

        // Disable canonical mode, echo, and signal generation
        raw.c_lflag &= ~tcflag_t(ICANON | ECHO | ISIG)
        // Disable input processing
        raw.c_iflag &= ~tcflag_t(IXON | ICRNL)
        // Read byte-at-a-time, no timeout
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
