/*
 * vsock-term: Guest-side terminal daemon for SafeYolo microVMs.
 *
 * Listens on vsock port 1024 (data) and 1025 (control/resize).
 * On connection: allocates a PTY, runs the specified command,
 * bridges I/O between vsock and the PTY master.
 *
 * Resize messages on port 1025: 4 bytes (rows_hi, rows_lo, cols_hi, cols_lo).
 *
 * Usage: vsock-term <command> [args...]
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#include <pty.h>

/* Linux vsock headers */
#include <linux/vm_sockets.h>
#define VSOCK_DATA_PORT 1024
#define VSOCK_CTRL_PORT 1025

static volatile sig_atomic_t child_exited = 0;
static pid_t child_pid = -1;

static void sigchld_handler(int sig) {
    (void)sig;
    child_exited = 1;
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
        perror("vsock bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 1) < 0) {
        perror("vsock listen");
        close(fd);
        return -1;
    }
    return fd;
}

static int vsock_accept(int listen_fd) {
    struct sockaddr_vm addr;
    socklen_t len = sizeof(addr);
    return accept(listen_fd, (struct sockaddr *)&addr, &len);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    signal(SIGCHLD, sigchld_handler);

    /* Listen on data and control ports */
    int data_listen = vsock_listen(VSOCK_DATA_PORT);
    int ctrl_listen = vsock_listen(VSOCK_CTRL_PORT);
    if (data_listen < 0) return 1;
    /* ctrl_listen failure is non-fatal — resize just won't work */

    fprintf(stderr, "vsock-term: listening on ports %d (data) %d (ctrl)\n",
            VSOCK_DATA_PORT, VSOCK_CTRL_PORT);

    /* Wait for data connection from host */
    int data_fd = vsock_accept(data_listen);
    if (data_fd < 0) { perror("accept data"); return 1; }
    close(data_listen);
    fprintf(stderr, "vsock-term: data connection established\n");

    /* Accept control connection and wait for initial window size.
     * This ensures the PTY has the correct size BEFORE the child starts. */
    int ctrl_fd = -1;
    struct winsize initial_ws = { .ws_row = 24, .ws_col = 80 };
    if (ctrl_listen >= 0) {
        /* Block waiting for control connection (up to 10s) */
        struct pollfd pfd = { .fd = ctrl_listen, .events = POLLIN };
        if (poll(&pfd, 1, 10000) > 0) {
            ctrl_fd = vsock_accept(ctrl_listen);
            if (ctrl_fd >= 0) {
                close(ctrl_listen);
                ctrl_listen = -1;
                fprintf(stderr, "vsock-term: ctrl connection established\n");

                /* Read initial window size (4 bytes: rows_hi, rows_lo, cols_hi, cols_lo) */
                unsigned char resize_buf[4];
                struct pollfd rpfd = { .fd = ctrl_fd, .events = POLLIN };
                if (poll(&rpfd, 1, 5000) > 0) {
                    if (read(ctrl_fd, resize_buf, 4) == 4) {
                        initial_ws.ws_row = (resize_buf[0] << 8) | resize_buf[1];
                        initial_ws.ws_col = (resize_buf[2] << 8) | resize_buf[3];
                        fprintf(stderr, "vsock-term: initial size %dx%d\n",
                                initial_ws.ws_col, initial_ws.ws_row);
                    }
                }
                fcntl(ctrl_fd, F_SETFL, O_NONBLOCK);
            }
        }
    }

    /* Allocate PTY with correct initial size and fork */
    int pty_master;
    child_pid = forkpty(&pty_master, NULL, NULL, &initial_ws);
    if (child_pid < 0) {
        perror("forkpty");
        close(data_fd);
        return 1;
    }

    if (child_pid == 0) {
        /* Child: run the command in the PTY */
        close(data_fd);
        if (ctrl_fd >= 0) close(ctrl_fd);
        if (ctrl_listen >= 0) close(ctrl_listen);

        /* Set terminal type for proper TUI rendering */
        setenv("TERM", "xterm-256color", 1);

        /* Wait for parent to set PTY size via master */
        usleep(200000);  /* 200ms */

        /* Check what size we see on the slave side */
        struct winsize child_ws;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &child_ws) == 0) {
            fprintf(stderr, "vsock-term child: slave size %dx%d\n",
                    child_ws.ws_col, child_ws.ws_row);
        }

        /* Force the size from the slave side too, belt and suspenders */
        ioctl(STDIN_FILENO, TIOCSWINSZ, &initial_ws);

        execvp(argv[1], &argv[1]);
        perror("vsock-term child: execvp failed");
        _exit(127);
    }

    /* Parent: set PTY size from master side and verify */
    usleep(100000);  /* 100ms — let child start before resize */
    if (ioctl(pty_master, TIOCSWINSZ, &initial_ws) < 0) {
        perror("vsock-term: TIOCSWINSZ set failed");
    }
    /* Verify it took */
    struct winsize verify;
    if (ioctl(pty_master, TIOCGWINSZ, &verify) == 0) {
        fprintf(stderr, "vsock-term: pty master verified: %dx%d\n", verify.ws_col, verify.ws_row);
    }
    /* Notify child to re-read terminal size */
    kill(child_pid, SIGWINCH);

    /* Bridge vsock ↔ PTY master */
    fcntl(pty_master, F_SETFL, O_NONBLOCK);
    fcntl(data_fd, F_SETFL, O_NONBLOCK);

    char buf[4096];
    int nfds = ctrl_fd >= 0 ? 3 : 2;

    while (!child_exited) {
        struct pollfd fds[3];
        fds[0].fd = data_fd;
        fds[0].events = POLLIN;
        fds[1].fd = pty_master;
        fds[1].events = POLLIN;
        if (ctrl_listen >= 0 && ctrl_fd < 0) {
            fds[2].fd = ctrl_listen;
            fds[2].events = POLLIN;
        } else if (ctrl_fd >= 0) {
            fds[2].fd = ctrl_fd;
            fds[2].events = POLLIN;
        } else {
            fds[2].fd = -1;
            fds[2].events = 0;
        }

        int ret = poll(fds, nfds, 500);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* vsock data → PTY (host typing) */
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(data_fd, buf, sizeof(buf));
            if (n > 0) write(pty_master, buf, n);
            else if (n == 0) break;
        }

        /* PTY → vsock data (command output) */
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(pty_master, buf, sizeof(buf));
            if (n > 0) write(data_fd, buf, n);
            else if (n == 0) break;
        }

        /* Accept control connection if pending */
        if (ctrl_listen >= 0 && ctrl_fd < 0 && (fds[2].revents & POLLIN)) {
            ctrl_fd = vsock_accept(ctrl_listen);
            if (ctrl_fd >= 0) {
                close(ctrl_listen);
                ctrl_listen = -1;
                fcntl(ctrl_fd, F_SETFL, O_NONBLOCK);
                fprintf(stderr, "vsock-term: ctrl connection established\n");
            }
        }

        /* Handle resize from control channel */
        if (ctrl_fd >= 0 && (fds[2].revents & POLLIN)) {
            unsigned char resize_buf[4];
            ssize_t n = read(ctrl_fd, resize_buf, 4);
            if (n == 4) {
                struct winsize ws;
                ws.ws_row = (resize_buf[0] << 8) | resize_buf[1];
                ws.ws_col = (resize_buf[2] << 8) | resize_buf[3];
                ws.ws_xpixel = 0;
                ws.ws_ypixel = 0;
                ioctl(pty_master, TIOCSWINSZ, &ws);
                kill(child_pid, SIGWINCH);
            }
        }

        /* Check for errors */
        if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLHUP)) {
            fprintf(stderr, "vsock-term: poll error/hangup (data=0x%x pty=0x%x)\n",
                    fds[0].revents, fds[1].revents);
            break;
        }
    }

    /* Wait for child and report exit status */
    int status = 0;
    waitpid(child_pid, &status, 0);
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

    close(pty_master);
    close(data_fd);
    if (ctrl_fd >= 0) close(ctrl_fd);
    if (ctrl_listen >= 0) close(ctrl_listen);

    fprintf(stderr, "vsock-term: exiting (code=%d)\n", exit_code);
    return exit_code;
}
