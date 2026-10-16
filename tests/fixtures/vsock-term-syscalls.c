/* Test-only transport and setup-failure injection for the real terminal child. */
#include <errno.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int __real_socket(int, int, int);
int __real_chdir(const char *);
int __real_setgid(gid_t);
int __real_initgroups(const char *, gid_t);
int __real_setuid(uid_t);

int __wrap_socket(int domain, int type, int protocol) {
    static int vsock_calls;
    if (domain != AF_VSOCK) return __real_socket(domain, type, protocol);
    if (vsock_calls++ == 0) return dup(atoi(getenv("TEST_TERMINAL_SOCKET")));
    errno = EAFNOSUPPORT;  /* The optional resize connection is absent. */
    return -1;
}

int __wrap_bind(int fd, const struct sockaddr *address, socklen_t length) {
    (void)fd; (void)address; (void)length;
    return 0;
}

int __wrap_listen(int fd, int backlog) {
    (void)fd; (void)backlog;
    return 0;
}

int __wrap_accept(int fd, struct sockaddr *address, socklen_t *length) {
    (void)address; (void)length;
    return dup(fd);
}

static int fail_setup(const char *stage) {
    const char *failure = getenv("TEST_TERMINAL_FAILURE");
    if (!failure || strcmp(failure, stage) != 0) return 0;
    errno = EACCES;
    return 1;
}

int __wrap_chdir(const char *path) {
    return fail_setup("chdir") ? -1 : __real_chdir(path);
}

int __wrap_setgid(gid_t gid) {
    return fail_setup("setgid") ? -1 : __real_setgid(gid);
}

int __wrap_initgroups(const char *user, gid_t gid) {
    return fail_setup("initgroups") ? -1 : __real_initgroups(user, gid);
}

int __wrap_setuid(uid_t uid) {
    return fail_setup("setuid") ? -1 : __real_setuid(uid);
}
