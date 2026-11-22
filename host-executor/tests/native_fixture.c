#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Prepared by the developer test, never by target discovery/qualification. */
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    setbuf(stdout, NULL);
    if (!strcmp(argv[1], "observe")) {
        gid_t groups[128];
        int count = getgroups(128, groups);
        if (count < 0) return 9;
        printf("uid=%u gid=%u groups=", getuid(), getgid());
        for (int i = 0; i < count; ++i) printf("%s%u", i ? "," : "", groups[i]);
        puts("");
        char resolved[PATH_MAX];
        int canonical = realpath(argv[2], resolved) != NULL;
        printf("canonical=%d\n", canonical);
        FILE *allowed = fopen(argv[2], "r");
        FILE *forbidden = fopen(argv[3], "r");
        char destination[PATH_MAX];
        if (snprintf(destination, sizeof(destination), "%s.written", argv[3]) >= (int)sizeof(destination)) return 10;
        FILE *write = fopen(destination, "w");
        int net = socket(AF_INET, SOCK_STREAM, 0);
        int ipc = socket(AF_UNIX, SOCK_STREAM, 0);
#ifdef __APPLE__
        // Seatbelt mediates connect rather than creation of a socket. EPERM
        // distinguishes policy denial from a missing loopback listener/path.
        struct sockaddr_in address = { .sin_len=sizeof(address), .sin_family=AF_INET, .sin_port=htons(1), .sin_addr.s_addr=htonl(INADDR_LOOPBACK) };
        if (net >= 0) { int fd=net; int r=connect(fd,(struct sockaddr *)&address,sizeof(address)); net=(r < 0 && errno==EPERM) ? -1 : 0; close(fd); }
        struct sockaddr_un unix_address = { .sun_len=sizeof(unix_address), .sun_family=AF_UNIX };
        if (snprintf(unix_address.sun_path,sizeof(unix_address.sun_path),"%s.socket",argv[3]) >= (int)sizeof(unix_address.sun_path)) return 11;
        if (ipc >= 0) { int fd=ipc; int r=connect(fd,(struct sockaddr *)&unix_address,sizeof(unix_address)); ipc=(r < 0 && errno==EPERM) ? -1 : 0; close(fd); }
        int huge_refused=1; // Linux-only control below; no macOS HugeTLB claim.
#else
        void *huge = mmap(NULL, 2*1024*1024, PROT_READ|PROT_WRITE,
                          MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
        int huge_refused = huge == MAP_FAILED && errno == EPERM;
        if (huge != MAP_FAILED) munmap(huge, 2*1024*1024);
        #endif
        printf("huge_refused=%d\n", huge_refused);
        printf("allowed=%d forbidden=%d write=%d net=%d ipc=%d fixture=%s home=%s\n",
               allowed != NULL, forbidden != NULL, write != NULL, net, ipc,
               getenv("FIXTURE") ? getenv("FIXTURE") : "absent",
               getenv("HOME") ? getenv("HOME") : "absent");
        return canonical && allowed && !forbidden && !write && net == -1 && ipc == -1 && huge_refused
            && getenv("FIXTURE") && !strcmp(getenv("FIXTURE"), "native")
            && !getenv("HOME") ? 0 : 3;
    }
    if (!strcmp(argv[1], "flood")) {
        for (;;) puts("bounded-native-output");
    }
    if (!strcmp(argv[1], "memory")) {
        for (;;) {
            volatile char *data = malloc(1024 * 1024);
            if (!data) return 4;
            for (int i = 0; i < 1024 * 1024; i += 4096) data[i] = 1;
        }
    }
    if (!strcmp(argv[1], "tasks")) {
        for (int i = 0; i < 100; ++i) {
            pid_t pid = fork();
            if (pid == 0) { for (;;) pause(); }
            if (pid < 0) {
                int error = errno;
                printf("fork_refused=%d\n", error);
                return error ==
#ifdef __APPLE__
                  EPERM
#else
                  EAGAIN
#endif
                  ? 0 : 5;
            }
        }
        return 6;
    }
    if (!strcmp(argv[1], "background") || !strcmp(argv[1], "wait")) {
#ifdef __APPLE__
        if (!strcmp(argv[1], "wait")) { alarm(4); puts("started"); for (;;) pause(); }
#endif
        pid_t pid = fork();
        if (pid < 0) {
#ifdef __APPLE__
            return errno==EPERM ? 0 : 7;
#else
            return 7;
#endif
        }
        if (pid == 0) { for (;;) pause(); }
        puts("started");
        if (!strcmp(argv[1], "background")) return 0;
        for (;;) pause();
    }
    return 8;
}
