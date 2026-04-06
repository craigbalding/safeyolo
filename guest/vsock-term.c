/*
 * vsock-term: Guest-side terminal daemon for SafeYolo microVMs.
 *
 * Listens on vsock port 1024 (data) and 1025 (control/resize).
 * On connection: allocates a PTY via openpty, forks, sets up the child
 * session and controlling terminal, drops to the agent user, and execs
 * the command directly (no shell wrapper).
 *
 * Resize messages on port 1025: 4 bytes (rows_hi, rows_lo, cols_hi, cols_lo).
 *
 * Usage: vsock-term [--uid N] [--gid N] [--home DIR] [--cwd DIR] <command> [args...]
 *
 * Build (ARM64 Linux, static):
 *   cc -static -O2 -o vsock-term vsock-term.c -lutil
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#include <pty.h>
#include <linux/vm_sockets.h>

#define VSOCK_DATA_PORT 1024
#define VSOCK_CTRL_PORT 1025

static volatile sig_atomic_t child_exited = 0;
static pid_t child_pid = -1;

static void sigchld_handler(int sig) {
    (void)sig;
    child_exited = 1;
}

/* Write all bytes, retrying on partial writes and EAGAIN/EINTR. */
static ssize_t write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n > 0) {
            p += n;
            remaining -= n;
        } else if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) {
                /* fd is non-blocking and buffer is full — poll until writable */
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                poll(&pfd, 1, 100);
                continue;
            }
            return -1;
        }
    }
    return len;
}

/* Read exactly n bytes, retrying on partial reads. */
static ssize_t read_exact(int fd, void *buf, size_t len, int timeout_ms) {
    char *p = buf;
    size_t got = 0;
    while (got < len) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, timeout_ms) <= 0) break;
        ssize_t n = read(fd, p + got, len - got);
        if (n <= 0) break;
        got += n;
    }
    return got;
}

static int vsock_listen(unsigned int port) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) { perror("vsock socket"); return -1; }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_port = port;
    addr.svm_cid = VMADDR_CID_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("vsock bind"); close(fd); return -1;
    }
    if (listen(fd, 1) < 0) {
        perror("vsock listen"); close(fd); return -1;
    }
    return fd;
}

static int vsock_accept(int listen_fd) {
    struct sockaddr_vm addr;
    socklen_t len = sizeof(addr);
    return accept(listen_fd, (struct sockaddr *)&addr, &len);
}

int main(int argc, char *argv[]) {
    uid_t uid = 1000;
    gid_t gid = 1000;
    const char *home = "/home/agent";
    const char *cwd = "/workspace";
    int cmd_start = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--uid") == 0 && i + 1 < argc) {
            uid = atoi(argv[++i]); cmd_start = i + 1;
        } else if (strcmp(argv[i], "--gid") == 0 && i + 1 < argc) {
            gid = atoi(argv[++i]); cmd_start = i + 1;
        } else if (strcmp(argv[i], "--home") == 0 && i + 1 < argc) {
            home = argv[++i]; cmd_start = i + 1;
        } else if (strcmp(argv[i], "--cwd") == 0 && i + 1 < argc) {
            cwd = argv[++i]; cmd_start = i + 1;
        } else {
            cmd_start = i;
            break;
        }
    }

    if (cmd_start >= argc) {
        fprintf(stderr, "Usage: %s [--uid N] [--gid N] [--home DIR] [--cwd DIR] <cmd> [args...]\n", argv[0]);
        return 1;
    }

    signal(SIGCHLD, sigchld_handler);

    int data_listen = vsock_listen(VSOCK_DATA_PORT);
    int ctrl_listen = vsock_listen(VSOCK_CTRL_PORT);
    if (data_listen < 0) return 1;

    /* Wait for data connection */
    int data_fd = vsock_accept(data_listen);
    if (data_fd < 0) { perror("accept data"); return 1; }
    close(data_listen);

    /* Accept control connection and read initial window size */
    int ctrl_fd = -1;
    struct winsize ws = { .ws_row = 24, .ws_col = 80, .ws_xpixel = 0, .ws_ypixel = 0 };

    if (ctrl_listen >= 0) {
        struct pollfd pfd = { .fd = ctrl_listen, .events = POLLIN };
        if (poll(&pfd, 1, 10000) > 0) {
            ctrl_fd = vsock_accept(ctrl_listen);
            if (ctrl_fd >= 0) {
                close(ctrl_listen); ctrl_listen = -1;
                unsigned char rbuf[4];
                if (read_exact(ctrl_fd, rbuf, 4, 5000) == 4) {
                    ws.ws_row = (rbuf[0] << 8) | rbuf[1];
                    ws.ws_col = (rbuf[2] << 8) | rbuf[3];
                }
            }
        }
    }

    /* Allocate PTY with initial size */
    int master_fd, slave_fd;
    if (openpty(&master_fd, &slave_fd, NULL, NULL, &ws) < 0) {
        perror("openpty"); close(data_fd); return 1;
    }

    child_pid = fork();
    if (child_pid < 0) {
        perror("fork"); close(master_fd); close(slave_fd); close(data_fd); return 1;
    }

    if (child_pid == 0) {
        /* === CHILD === */
        close(master_fd);
        close(data_fd);
        if (ctrl_fd >= 0) close(ctrl_fd);
        if (ctrl_listen >= 0) close(ctrl_listen);

        /* New session + controlling terminal */
        setsid();
        ioctl(slave_fd, TIOCSCTTY, 0);
        dup2(slave_fd, 0);
        dup2(slave_fd, 1);
        dup2(slave_fd, 2);
        if (slave_fd > 2) close(slave_fd);
        for (int fd = 3; fd < 1024; fd++) close(fd);

        /* Environment */
        setenv("TERM", "xterm-256color", 1);
        setenv("HOME", home, 1);
        setenv("USER", "agent", 1);
        setenv("SHELL", "/bin/bash", 1);
        setenv("LANG", "C.UTF-8", 1);
        /* mise paths — so the child can find installed tools */
        setenv("MISE_DATA_DIR", "/opt/mise", 1);
        setenv("MISE_CONFIG_DIR", "/opt/mise", 1);
        setenv("MISE_CACHE_DIR", "/opt/mise/cache", 1);
        setenv("PATH", "/opt/mise/shims:/usr/local/bin:/usr/bin:/bin", 1);

        /* Source proxy/agent env if present */
        /* These were written to /etc/environment by the guest init */

        chdir(cwd);

        /* Drop privileges */
        setgid(gid);
        initgroups("agent", gid);
        setuid(uid);

        /* Exec the command directly — no shell wrapper */
        execvp(argv[cmd_start], &argv[cmd_start]);
        perror("vsock-term: exec failed");
        _exit(127);
    }

    /* === PARENT === */
    close(slave_fd);

    /* Keep fds BLOCKING for the bridge — prevents partial writes.
     * Use poll() to check readability before read(). */
    /* master_fd and data_fd stay blocking */

    char buf[16384];  /* Larger buffer for TUI bursts */

    /* Bridge loop: vsock data ↔ PTY master */
    while (!child_exited) {
        struct pollfd fds[3];
        int nfds = 2;
        fds[0].fd = data_fd;   fds[0].events = POLLIN;
        fds[1].fd = master_fd; fds[1].events = POLLIN;
        if (ctrl_fd >= 0) {
            fds[2].fd = ctrl_fd; fds[2].events = POLLIN;
            nfds = 3;
        }

        int ret = poll(fds, nfds, 200);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* vsock → PTY (host typing) */
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(data_fd, buf, sizeof(buf));
            if (n > 0) write_all(master_fd, buf, n);
            else if (n == 0) break;
        }

        /* PTY → vsock (guest output) */
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(master_fd, buf, sizeof(buf));
            if (n > 0) write_all(data_fd, buf, n);
            else if (n == 0) break;
        }

        /* Resize from control channel */
        if (nfds > 2 && (fds[2].revents & POLLIN)) {
            unsigned char rbuf[4];
            if (read_exact(ctrl_fd, rbuf, 4, 100) == 4) {
                struct winsize nws = {
                    .ws_row = (rbuf[0] << 8) | rbuf[1],
                    .ws_col = (rbuf[2] << 8) | rbuf[3],
                };
                ioctl(master_fd, TIOCSWINSZ, &nws);
                kill(child_pid, SIGWINCH);
            }
        }

        if ((fds[0].revents | fds[1].revents) & POLLERR) break;
        /* Don't break on POLLHUP from PTY — drain remaining data first */
    }

    /* Drain remaining PTY output after child exits */
    for (;;) {
        struct pollfd pfd = { .fd = master_fd, .events = POLLIN };
        if (poll(&pfd, 1, 100) <= 0) break;
        ssize_t n = read(master_fd, buf, sizeof(buf));
        if (n <= 0) break;
        write_all(data_fd, buf, n);
    }

    int status = 0;
    waitpid(child_pid, &status, 0);
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

    close(master_fd);
    close(data_fd);
    if (ctrl_fd >= 0) close(ctrl_fd);

    return exit_code;
}
