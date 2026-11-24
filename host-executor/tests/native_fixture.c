#define _GNU_SOURCE
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

#ifdef __linux__
static int tcp_probe(const char *mode, const char *directory, int local_port, int remote_port) {
    int outbound = strstr(mode,"connect") || strstr(mode,"both");
    int listener = strstr(mode,"listen") || strstr(mode,"both") || strstr(mode,"wait");
    int ipv6 = mode[strlen(mode)-1]=='6';
    int family = ipv6 ? AF_INET6 : AF_INET;
    struct sockaddr_in v4 = { .sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK) };
    struct sockaddr_in6 v6 = { .sin6_family=AF_INET6, .sin6_addr=IN6ADDR_LOOPBACK_INIT };
    struct sockaddr *address = ipv6 ? (struct sockaddr *)&v6 : (struct sockaddr *)&v4;
    socklen_t length = ipv6 ? sizeof(v6) : sizeof(v4);
    v4.sin_port=htons((unsigned short)remote_port);
    v6.sin6_port=htons((unsigned short)remote_port);
    if (socket(AF_UNIX,SOCK_STREAM,0)!=-1 || errno!=EPERM) return 60;
    if (socket(family,SOCK_DGRAM,0)!=-1 || errno!=EPERM) return 61;
    if (socket(family,SOCK_STREAM,IPPROTO_MPTCP)!=-1 || errno!=EPERM) return 62;
    if (outbound) {
        pid_t child=fork();
        if (child<0) return 63;
        int fd=socket(family,SOCK_STREAM|SOCK_CLOEXEC,IPPROTO_TCP);
        char answer[2];
        if (fd<0 || connect(fd,address,length) || write(fd,"request",7)!=7
            || recv(fd,answer,2,MSG_WAITALL)!=2 || memcmp(answer,"ok",2)) {
            if (!child) _exit(64);
            return 64;
        }
        close(fd);
        if (!child) _exit(0);
        int status;
        if (waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)) return 65;
        puts("outbound request and descendant request completed");
    } else {
        int fd=socket(family,SOCK_STREAM,0);
        if (fd<0) return 66;
        if (connect(fd,address,length)!=-1 || errno!=EPERM) return 67;
#ifdef __linux__
        char data='x';
        struct iovec iov = { .iov_base=&data, .iov_len=1 };
        struct msghdr message = { .msg_name=address, .msg_namelen=length, .msg_iov=&iov, .msg_iovlen=1 };
        struct mmsghdr messages = { .msg_hdr=message };
        if (sendto(fd,&data,1,MSG_FASTOPEN,address,length)!=-1 || errno!=EPERM) return 68;
        if (sendmsg(fd,&message,MSG_FASTOPEN)!=-1 || errno!=EPERM) return 69;
        if (sendmmsg(fd,&messages,1,MSG_FASTOPEN)!=-1 || errno!=EPERM) return 70;
#endif
        close(fd);
        puts("connect and TCP Fast Open denied");
    }
    int fd=socket(family,SOCK_STREAM|SOCK_CLOEXEC,0);
    if (fd<0) return 71;
    if (!listener) {
        /* Also covers implicit listen autobinding without bind(). */
        if (listen(fd,1)!=-1 || errno!=EPERM) return 72;
        if (accept(fd,NULL,NULL)!=-1 || errno!=EPERM) return 73;
#ifdef __linux__
        if (accept4(fd,NULL,NULL,SOCK_CLOEXEC)!=-1 || errno!=EPERM) return 74;
#endif
        puts("listen and accept denied");
    } else {
        v4.sin_port=htons((unsigned short)local_port);
        v6.sin6_port=htons((unsigned short)local_port);
        if (bind(fd,address,length)) { printf("bind_failed_errno=%d\n",errno); return 75; }
        if (listen(fd,1)) return 76;
        printf("bound=%d family=%d\n",local_port,ipv6 ? 6 : 4);
        if (strstr(mode,"wait")) {
            pid_t child=fork();
            if (child<0) return 77;
            if (!child) {
                if (setsid()<0) _exit(78);
                puts("listening descendant ready");
                for (;;) pause();
            }
            close(fd);
            for (;;) pause();
        }
        struct timeval timeout = { .tv_sec=3 };
        if (setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))) return 79;
        int client=accept(fd,NULL,NULL);
        if (client<0 || write(client,"service",7)!=7) return 80;
        char byte;
        if (read(client,&byte,1)!=0) return 83;
        close(client);
    }
    close(fd);
    char path[PATH_MAX];
    if (snprintf(path,sizeof(path),"%s/%s",directory,mode)>=(int)sizeof(path)) return 81;
    FILE *file=fopen(path,"w");
    if (!file || fputs("retained TCP result\n",file)<0 || fclose(file)) return 82;
    return 0;
}
#endif

#ifdef __APPLE__
static int mac_network_probe(const char *mode, const char *directory, int local_port, int remote_port) {
    int outbound = strstr(mode,"connect") || strstr(mode,"both");
    int listener = strstr(mode,"listen") || strstr(mode,"both") || strstr(mode,"wait");
    int ipv6 = mode[strlen(mode)-1]=='6';
    int udp = strstr(mode,"udp") != NULL;
    int family = ipv6 ? AF_INET6 : AF_INET;
    int type = udp ? SOCK_DGRAM : SOCK_STREAM;
    struct sockaddr_in v4 = { .sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK) };
    struct sockaddr_in6 v6 = { .sin6_family=AF_INET6, .sin6_addr=IN6ADDR_LOOPBACK_INIT };
    struct sockaddr *address = ipv6 ? (struct sockaddr *)&v6 : (struct sockaddr *)&v4;
    socklen_t length = ipv6 ? sizeof(v6) : sizeof(v4);
    int ipc=socket(AF_UNIX,SOCK_STREAM,0);
    if (ipc>=0) {
        struct sockaddr_un unix_address={.sun_family=AF_UNIX};
        if (snprintf(unix_address.sun_path,sizeof(unix_address.sun_path),"%s/probe.socket",directory)>=(int)sizeof(unix_address.sun_path)) return 90;
        if (bind(ipc,(struct sockaddr *)&unix_address,sizeof(unix_address))!=-1 || errno!=EPERM) {
            perror("forbidden Unix bind"); return 90;
        }
        if (snprintf(unix_address.sun_path,sizeof(unix_address.sun_path),"%s/../forbidden.socket",directory)>=(int)sizeof(unix_address.sun_path)) return 90;
        if (connect(ipc,(struct sockaddr *)&unix_address,sizeof(unix_address))!=-1 || errno!=EPERM) {
            perror("forbidden Unix connect"); return 90;
        }
        close(ipc);
    } else if (errno!=EPERM) { perror("Unix socket"); return 90; }
    if (socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)!=-1 || errno!=EPERM) return 91;
    if (fork()!=-1 || errno!=EPERM) return 92;
    if (getenv("DENIED_TCP_PORT")) {
        struct sockaddr_in denied = { .sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK),
            .sin_port=htons((unsigned short)atoi(getenv("DENIED_TCP_PORT"))) };
        int fd=socket(AF_INET,SOCK_STREAM,0);
        if (fd!=-1) {
            if (connect(fd,(struct sockaddr *)&denied,sizeof(denied))!=-1 || errno!=EPERM) return 93;
            close(fd);
        }
        fd=socket(AF_INET,type,0);
        if (fd!=-1) {
            if (bind(fd,(struct sockaddr *)&denied,sizeof(denied))!=-1 || errno!=EPERM) return 107;
            close(fd);
        }
    }
    v4.sin_port=htons((unsigned short)remote_port);
    v6.sin6_port=htons((unsigned short)remote_port);
    int fd=socket(family,type,0);
    if (fd<0) { perror("socket"); return 94; }
    if (outbound) {
        struct timeval timeout={.tv_sec=3};
        if (setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))) return 95;
        char answer[2];
        if (connect(fd,address,length) || write(fd,"request",7)!=7
            || recv(fd,answer,2,udp ? 0 : MSG_WAITALL)!=2 || memcmp(answer,"ok",2)) {
            perror("outbound"); return 96;
        }
        puts("selected outbound request completed");
    } else if (connect(fd,address,length)!=-1 || errno!=EPERM) return 97;
    close(fd);
    fd=socket(family,type,0);
    v4.sin_port=htons((unsigned short)local_port);
    v6.sin6_port=htons((unsigned short)local_port);
    if (listener) {
        if (bind(fd,address,length)) { printf("bind_failed_errno=%d\n",errno); return 98; }
        if (!udp && listen(fd,1)) { perror("listen"); return 99; }
        printf("bound=%d family=%d\n",local_port,ipv6 ? 6 : 4);
        char path[PATH_MAX];
        if (snprintf(path,sizeof(path),"%s/%s",directory,mode)>=(int)sizeof(path)) return 100;
        FILE *file=fopen(path,"w");
        if (!file || fputs("retained network result\n",file)<0 || fclose(file)) return 101;
        if (strstr(mode,"wait")) { alarm(8); for (;;) pause(); }
        struct timeval timeout={.tv_sec=3};
        if (setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))) return 102;
        if (udp) {
            char data[7];
            if (recv(fd,data,7,0)!=7 || memcmp(data,"request",7)) return 103;
        } else {
            int peer=accept(fd,NULL,NULL);
            if (peer<0 || write(peer,"service",7)!=7) { perror("accept/reply"); return 104; }
            char byte;
            if (read(peer,&byte,1)!=0) return 106;
            close(peer);
        }
    } else if (bind(fd,address,length)!=-1 || errno!=EPERM) return 105;
    close(fd);
    puts("selected socket directions and ports enforced; Unix bind/connect, raw sockets and fork denied");
    return 0;
}
#endif

/* Prepared by the developer test, never by target discovery/qualification. */
static int handoff_probe(const char *mode, const char *directory, int forbidden_port) {
    struct sockaddr_storage address;
    socklen_t size=sizeof(address);
    if (getsockname(3,(struct sockaddr *)&address,&size)) { perror("inherited listener"); return 110; }
    int extra=socket(AF_INET,SOCK_STREAM,0);
    if (extra!=-1 || errno!=EPERM) { if (extra>=0) close(extra); return 111; }
    struct sockaddr_in forbidden={ .sin_family=AF_INET, .sin_port=htons((unsigned short)forbidden_port),
        .sin_addr.s_addr=htonl(INADDR_LOOPBACK) };
    if (connect(3,(struct sockaddr *)&forbidden,sizeof(forbidden))!=-1) return 112;
    char path[PATH_MAX];
    if (snprintf(path,sizeof(path),"%s/result",directory)>=(int)sizeof(path)) return 113;
    FILE *result=fopen(path,"w");
    if (!result || fputs("service started with inherited listener\n",result)<0 || fclose(result)) return 114;
    puts("application ready to accept on inherited listener");
    /* Bound this development fixture after a controller-crash test. The
       product does not infer an alarm or cleanup guarantee from this probe. */
    alarm(4);
    if (strstr(mode,"wait")) for (;;) pause();
    int peer=accept(3,NULL,NULL);
    if (peer<0 || write(peer,"service",7)!=7) { perror("inherited accept"); return 115; }
    close(peer);
    close(3);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    setbuf(stdout, NULL);
    if (!strncmp(argv[1],"handoff",7)) return handoff_probe(argv[1],argv[2],atoi(argv[4]));
#ifdef __linux__
    if (!strncmp(argv[1],"tcp-",4)) return tcp_probe(argv[1],argv[2],atoi(argv[3]),atoi(argv[4]));
#endif
#ifdef __APPLE__
    if (!strncmp(argv[1],"mac-net-",8)) return mac_network_probe(argv[1],argv[2],atoi(argv[3]),atoi(argv[4]));
#endif
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
#ifdef __APPLE__
        if (!strncmp(argv[1],"write-single",12)) {
            if (fork()!=-1 || errno!=EPERM) return 47;
            puts("created, replaced, modified, removed; outside write/link and fork denied");
            if (strstr(argv[1],"wait")) { alarm(4); for (;;) pause(); }
            if (strstr(argv[1],"flood")) { for (int i=0;i<10000;i++) puts("output"); }
            return strstr(argv[1],"partial") ? 46 : 0;
        }
#endif
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
