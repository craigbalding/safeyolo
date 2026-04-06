/*
 * feth-bridge: Forward Ethernet frames between a Unix socket fd and a
 * feth interface via BPF.
 *
 * Used by safeyolo-vm to connect a VM's VZFileHandleNetworkDeviceAttachment
 * to a feth pair where pf rules can enforce network isolation.
 *
 * Usage: sudo feth-bridge <socket-fd> <feth-interface>
 *
 * The socket-fd is inherited from the parent process (safeyolo-vm) and
 * carries raw Ethernet frames as Unix datagrams.
 *
 * Build: cc -O2 -o feth-bridge feth-bridge.c
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/bpf.h>
#include <net/if.h>

#define MAX_FRAME_SIZE 65536

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

/*
 * Open a BPF device and attach it to an interface.
 * Returns the BPF fd, or -1 on error.
 */
static int open_bpf(const char *ifname) {
    int fd = -1;
    char bpfdev[32];

    /* Find an available /dev/bpf device */
    for (int i = 0; i < 256; i++) {
        snprintf(bpfdev, sizeof(bpfdev), "/dev/bpf%d", i);
        fd = open(bpfdev, O_RDWR);
        if (fd >= 0) break;
        if (errno != EBUSY) {
            fprintf(stderr, "feth-bridge: open %s: %s\n", bpfdev, strerror(errno));
            return -1;
        }
    }
    if (fd < 0) {
        fprintf(stderr, "feth-bridge: no available /dev/bpf devices\n");
        return -1;
    }

    /* Attach to interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        fprintf(stderr, "feth-bridge: BIOCSETIF %s: %s\n", ifname, strerror(errno));
        close(fd);
        return -1;
    }

    /* Enable immediate mode (don't buffer reads) */
    int imm = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &imm) < 0) {
        fprintf(stderr, "feth-bridge: BIOCIMMEDIATE: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* See sent packets (so we can capture responses) */
    int seesent = 1;
    if (ioctl(fd, BIOCSSEESENT, &seesent) < 0) {
        /* Non-fatal — some BPF versions don't support this */
    }

    /* Enable header-complete mode (we provide full Ethernet headers) */
    int hdrcmplt = 1;
    if (ioctl(fd, BIOCSHDRCMPLT, &hdrcmplt) < 0) {
        fprintf(stderr, "feth-bridge: BIOCSHDRCMPLT: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Get BPF buffer length */
    unsigned int buflen;
    if (ioctl(fd, BIOCGBLEN, &buflen) < 0) {
        fprintf(stderr, "feth-bridge: BIOCGBLEN: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Set non-blocking for poll */
    fcntl(fd, F_SETFL, O_NONBLOCK);

    fprintf(stderr, "feth-bridge: attached to %s (bpf buf=%u)\n", ifname, buflen);
    return fd;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <socket-fd> <feth-interface>\n", argv[0]);
        return 1;
    }

    int sock_fd = atoi(argv[1]);
    const char *ifname = argv[2];

    /* Validate socket fd */
    if (fcntl(sock_fd, F_GETFD) < 0) {
        fprintf(stderr, "feth-bridge: fd %d is not valid: %s\n", sock_fd, strerror(errno));
        return 1;
    }

    /* Open BPF on the feth interface */
    int bpf_fd = open_bpf(ifname);
    if (bpf_fd < 0) return 1;

    /* Get BPF buffer size for reads */
    unsigned int bpf_buflen;
    ioctl(bpf_fd, BIOCGBLEN, &bpf_buflen);

    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr, "feth-bridge: forwarding fd=%d <-> %s\n", sock_fd, ifname);

    uint8_t sock_buf[MAX_FRAME_SIZE];
    uint8_t *bpf_buf = malloc(bpf_buflen);
    if (!bpf_buf) {
        perror("malloc");
        close(bpf_fd);
        return 1;
    }

    struct pollfd fds[2];
    fds[0].fd = sock_fd;
    fds[0].events = POLLIN;
    fds[1].fd = bpf_fd;
    fds[1].events = POLLIN;

    while (running) {
        int ret = poll(fds, 2, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("feth-bridge: poll");
            break;
        }
        if (ret == 0) continue;

        /* Socket → BPF (VM sending a frame) */
        if (fds[0].revents & POLLIN) {
            ssize_t n = recv(sock_fd, sock_buf, sizeof(sock_buf), 0);
            if (n > 0) {
                write(bpf_fd, sock_buf, n);
            } else if (n == 0) {
                fprintf(stderr, "feth-bridge: socket closed\n");
                break;
            }
        }

        /* BPF → Socket (frame arriving for the VM) */
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(bpf_fd, bpf_buf, bpf_buflen);
            if (n > 0) {
                /*
                 * BPF returns one or more frames, each with a bpf_hdr prefix.
                 * Walk the buffer extracting individual frames.
                 */
                uint8_t *p = bpf_buf;
                uint8_t *end = bpf_buf + n;
                while (p < end) {
                    struct bpf_hdr *hdr = (struct bpf_hdr *)p;
                    uint8_t *frame = p + hdr->bh_hdrlen;
                    uint32_t caplen = hdr->bh_caplen;

                    if (caplen > 0 && frame + caplen <= end) {
                        send(sock_fd, frame, caplen, 0);
                    }

                    /* Advance to next frame (BPF_WORDALIGN) */
                    p += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
                }
            }
        }

        /* Check for errors/hangup */
        if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLHUP)) {
            fprintf(stderr, "feth-bridge: fd error/hangup\n");
            break;
        }
    }

    fprintf(stderr, "feth-bridge: shutting down\n");
    free(bpf_buf);
    close(bpf_fd);
    close(sock_fd);
    return 0;
}
