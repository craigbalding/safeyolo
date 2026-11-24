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
#include <sys/stat.h>
#include <unistd.h>

/* Prepared by the developer test, never by target discovery/qualification. */
int main(int argc, char **argv) {
    if (argc != 5) return 2;
    setbuf(stdout, NULL);
    if (!strncmp(argv[1], "write-", 6)) {
        char path[PATH_MAX], replacement[PATH_MAX];
        if (snprintf(path,sizeof(path),"%s/new",argv[2]) >= (int)sizeof(path)
            || snprintf(replacement,sizeof(replacement),"%s/result",argv[2]) >= (int)sizeof(replacement)) return 30;
        FILE *output = fopen(path,"w");
        if (!output) return 31;
        if (fputs("retained result\n",output)<0 || fclose(output)) return 32;
        if (rename(path,replacement)) return 33;
        output=fopen(replacement,"a");
        if (!output || fputs("modified\n",output)<0 || fclose(output)) return 34;
        output=fopen(path,"w");
        if (!output || fclose(output) || unlink(path)) return 35;
        if (snprintf(path,sizeof(path),"%s/escape",argv[2]) >= (int)sizeof(path)) return 36;
        output=fopen(path,"w");
        if (output) { fclose(output); return 37; }
        if (snprintf(path,sizeof(path),"%s/read-alias",argv[2]) >= (int)sizeof(path)) return 38;
        if (!link(argv[3],path)) return 39;
        pid_t pid=fork();
        if (pid<0) return 40;
        if (pid==0) {
            if (!strcmp(argv[1],"write-wait")) {
                if (setsid()<0) _exit(41);
                if (snprintf(path,sizeof(path),"%s/background",argv[2]) >= (int)sizeof(path)) _exit(42);
                FILE *marker=fopen(path,"w");
                if (!marker || fprintf(marker,"%d\n",getpid())<0 || fclose(marker)) _exit(43);
                for (;;) pause();
            }
            execl("/usr/bin/printf","printf","child executed\\n",(char *)NULL);
            _exit(44);
        }
        if (!strcmp(argv[1],"write-wait")) { puts("started"); for (;;) pause(); }
        int status;
        if (waitpid(pid,&status,0)!=pid || !WIFEXITED(status) || WEXITSTATUS(status)) return 45;
        puts("created, replaced, modified, removed; outside write/link denied");
        return !strcmp(argv[1],"write-partial") ? 46 : 0;
    }
    if (!strcmp(argv[1], "read-config") || !strcmp(argv[1], "execute-config")) {
        FILE *input = fopen(argv[2], "r");
        if (!input) return 20;
        char data[128];
        size_t count = fread(data, 1, sizeof(data), input);
        int failed = ferror(input);
        fclose(input);
        if (failed || count == sizeof(data)) return 21;
        return fwrite(data, 1, count, stdout) == count ? 0 : 24;
    }
    if (!strcmp(argv[1], "write-config")) {
        FILE *output = fopen(argv[2], "w");
        if (!output) return 25;
        int written = fputs("enabled\n", output) >= 0;
        return fclose(output) || !written ? 26 : 0;
    }
    if (!strcmp(argv[1], "observe")) {
        puts("safeyolo-native-probe-revision=1");
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
        /* The parent owns live receivers and checks their accept queues before
         * and after this workload. A missing listener is not a denial oracle. */
        struct sockaddr_in address = { .sin_family=AF_INET, .sin_port=htons((unsigned short)strtoul(argv[4],NULL,10)), .sin_addr.s_addr=htonl(INADDR_LOOPBACK) };
#ifdef __APPLE__
        address.sin_len=sizeof(address);
#endif
        if (net >= 0) { int fd=net; net=connect(fd,(struct sockaddr *)&address,sizeof(address)); close(fd); }
        struct sockaddr_un unix_address = { .sun_family=AF_UNIX };
#ifdef __APPLE__
        unix_address.sun_len=sizeof(unix_address);
#endif
        if (snprintf(unix_address.sun_path,sizeof(unix_address.sun_path),"%s.socket",argv[3]) >= (int)sizeof(unix_address.sun_path)) return 11;
        if (ipc >= 0) { int fd=ipc; ipc=connect(fd,(struct sockaddr *)&unix_address,sizeof(unix_address)); close(fd); }
#ifdef __APPLE__
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
