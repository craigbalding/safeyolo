/*
 * bridge-filter: Enable pf IP filtering on a macOS bridge interface.
 *
 * macOS bridge interfaces have ipfilter disabled by default, meaning pf
 * rules on the bridge are silently ignored. This tool uses the BRDGSFILT
 * ioctl to set the IFBF_FILT_USEIPF flag from XNU's if_bridgevar.h.
 *
 * Usage: sudo bridge-filter <bridge-name>
 *
 * Build: cc -o bridge-filter bridge-filter.c
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/* From bsd/net/if_bridgevar.h (XNU kernel source) */
#define BRDGSFILT   24
#define BRDGGFILT   23

#define IFBF_FILT_USEIPF    0x00000001  /* run pf hooks on bridge */
#define IFBF_FILT_MEMBER    0x00000002  /* run pf hooks on members */
#define IFBF_FILT_ONLYIP    0x00000004  /* only filter IP packets */

/*
 * SIOCSDRVSPEC = _IOW('i', 124, struct ifdrv) = 0x8028697C
 * SIOCGDRVSPEC = _IOWR('i', 123, struct ifdrv) = 0xC0286977
 */
#ifndef SIOCSDRVSPEC
#define SIOCSDRVSPEC    0x8028697C
#endif
#ifndef SIOCGDRVSPEC
#define SIOCGDRVSPEC    0xC0286977
#endif

struct ifdrv {
    char        ifd_name[IFNAMSIZ];
    unsigned long   ifd_cmd;
    size_t      ifd_len;
    void        *ifd_data;
};

struct ifbrparam {
    union {
        uint32_t ifbrpu_int32;
        uint16_t ifbrpu_int16;
        uint8_t  ifbrpu_int8;
    } ifbrp_ifbrpu;
};
#define ifbrp_filter    ifbrp_ifbrpu.ifbrpu_int32

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bridge-name>\n", argv[0]);
        return 1;
    }

    const char *bridge = argv[1];
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    /* First, read current filter flags */
    struct ifbrparam gp;
    memset(&gp, 0, sizeof(gp));
    struct ifdrv gdrv;
    memset(&gdrv, 0, sizeof(gdrv));
    strlcpy(gdrv.ifd_name, bridge, IFNAMSIZ);
    gdrv.ifd_cmd = BRDGGFILT;
    gdrv.ifd_len = sizeof(gp);
    gdrv.ifd_data = &gp;

    if (ioctl(s, SIOCGDRVSPEC, &gdrv) < 0) {
        fprintf(stderr, "ioctl BRDGGFILT on %s: %s\n", bridge, strerror(errno));
        close(s);
        return 1;
    }

    uint32_t current = gp.ifbrp_filter;
    if (current & IFBF_FILT_USEIPF) {
        fprintf(stderr, "ipfilter already enabled on %s (flags=0x%x)\n", bridge, current);
        close(s);
        return 0;
    }

    /* Enable USEIPF flag */
    struct ifbrparam sp;
    memset(&sp, 0, sizeof(sp));
    sp.ifbrp_filter = current | IFBF_FILT_USEIPF;

    struct ifdrv sdrv;
    memset(&sdrv, 0, sizeof(sdrv));
    strlcpy(sdrv.ifd_name, bridge, IFNAMSIZ);
    sdrv.ifd_cmd = BRDGSFILT;
    sdrv.ifd_len = sizeof(sp);
    sdrv.ifd_data = &sp;

    if (ioctl(s, SIOCSDRVSPEC, &sdrv) < 0) {
        fprintf(stderr, "ioctl BRDGSFILT on %s: %s\n", bridge, strerror(errno));
        close(s);
        return 1;
    }

    fprintf(stderr, "ipfilter enabled on %s (flags=0x%x → 0x%x)\n",
            bridge, current, sp.ifbrp_filter);
    close(s);
    return 0;
}
