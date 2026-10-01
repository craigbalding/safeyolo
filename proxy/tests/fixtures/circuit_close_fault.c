#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Linux child-process test only. Restrict faults to the owned snapshot temp.
 * Log syscall categories only: never copy a path or data buffer into evidence. */
static const char *directory;
static const char *mode;
static const char *style;
static int log_fd = -1;
static _Atomic int released = -1;
static _Atomic int writes;
static int (*actual_close)(int);
static ssize_t (*actual_write)(int, const void *, size_t);
static void event(const char *line) {
    if (log_fd >= 0) (void) syscall(SYS_write, log_fd, line, strlen(line));
}
__attribute__((constructor)) static void initialize(void) {
    directory = getenv("CIRCUIT_FAULT_DIRECTORY");
    mode = getenv("CIRCUIT_FAULT_MODE");
    style = getenv("CIRCUIT_FAULT_STYLE");
    const char *log = getenv("CIRCUIT_FAULT_LOG");
    actual_close = dlsym(RTLD_NEXT, "close");
    actual_write = dlsym(RTLD_NEXT, "write");
    if (log) log_fd = (int) syscall(SYS_openat, AT_FDCWD, log,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
}
static bool owned(int fd) {
    if (!directory || !mode || fd == log_fd) return false;
    int saved = errno;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_WRONLY) { errno = saved; return false; }
    char descriptor[64], path[4096];
    int count = snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    if (count < 0 || (size_t) count >= sizeof(descriptor)) { errno = saved; return false; }
    ssize_t length = readlink(descriptor, path, sizeof(path) - 1);
    bool matches = false;
    if (length >= 0) {
        path[length] = '\0';
        size_t prefix = strlen(directory);
        if ((size_t) length > prefix && !strncmp(path, directory, prefix) && path[prefix] == '/') {
            const char *name = path + prefix + 1;
            size_t size = strlen(name);
            matches = style && !strcmp(style, "python")
                ? !strcmp(name, "state.tmp")
                : size > 13 && !strncmp(name, ".circuit-", 9)
                    && !strcmp(name + size - 4, ".tmp") && !strchr(name, '/');
        }
    }
    errno = saved;
    return matches;
}
ssize_t write(int fd, const void *bytes, size_t length) {
    if (!owned(fd)) return actual_write(fd, bytes, length);
    int ordinal = atomic_fetch_add(&writes, 1) + 1;
    if (!strcmp(mode, "write_only") || !strcmp(mode, "write_close") ||
        (!strcmp(mode, "short_close") && ordinal > 1)) {
        event("write_report_ENOSPC\n"); errno = ENOSPC; return -1;
    }
    size_t requested = !strcmp(mode, "short_close") && length > 7 ? 7 : length;
    ssize_t result = actual_write(fd, bytes, requested);
    event(result == (ssize_t) requested ? "write_real_success\n" : "write_real_failure\n");
    return result;
}
int close(int fd) {
    if (!owned(fd)) {
        int saved = errno;
        if (fd == atomic_load(&released) && fcntl(fd, F_GETFD) < 0 && errno == EBADF)
            event("repeat_close_after_release\n");
        errno = saved;
        return actual_close(fd);
    }
    int result = actual_close(fd); /* Release the actual owned descriptor once. */
    atomic_store(&released, fd);
    event(result == 0 ? "close_real_success\n" : "close_real_failure\n");
    if (strcmp(mode, "none") && strcmp(mode, "write_only")) {
        event("close_report_EIO\n"); errno = EIO; return -1;
    }
    return result;
}
