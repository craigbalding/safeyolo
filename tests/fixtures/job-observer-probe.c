/* Test-only Linux executable for the VZ job observer boundary.
 * On a Linux build host for the guest architecture:
 * cc -O2 -static -Wall -Wextra -Werror tests/fixtures/job-observer-probe.c -o /disk/observer-probe
 * Supply that file to the host driver with --observer-probe. No guest compiler
 * or interpreter is needed. This process must replace the fixed job command.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main(void) {
    pid_t observer = getppid();
    if (observer <= 1 || kill(observer, 0) != -1 || errno != EPERM) {
        fputs("job root has signal authority over its observer\n", stderr);
        return 1;
    }
    if (ptrace(PTRACE_ATTACH, observer, NULL, NULL) != -1 || errno != EPERM) {
        ptrace(PTRACE_DETACH, observer, NULL, NULL);
        fputs("job root can attach to its observer\n", stderr);
        return 1;
    }
    char key[128];
    snprintf(key, sizeof(key), "/proc/%ld/root/run/job-host-key", (long)observer);
    int fd = open(key, O_RDONLY);
    if (fd >= 0 || (errno != EACCES && errno != EPERM)) {
        fputs("observer key did not refuse access\n", stderr);
        return 1;
    }
    DIR *descriptors = opendir("/proc/self/fd");
    if (!descriptors) {
        perror("opendir /proc/self/fd");
        return 1;
    }
    struct dirent *entry;
    while ((entry = readdir(descriptors))) {
        if (entry->d_name[0] == '.') continue;
        fd = atoi(entry->d_name);
        if (fd > 2 && fd != dirfd(descriptors)) {
            fprintf(stderr, "inherited descriptor %d\n", fd);
            return 1;
        }
    }
    closedir(descriptors);
    puts("observer signal/ptrace/key access refused; no inherited descriptors");
    return 0;
}
