/* Test-only holder for live mount removal; the guest needs no interpreter.
 * On Linux with the guest's CPU architecture, from the repository root:
 * cc -std=c11 -O2 -static -Wall -Wextra -Werror tests/fixtures/live-mount-holder.c -o /disk/mount-holder
 * Supply that executable with --holder-probe or SAFEYOLO_MOUNT_HOLDER_PROBE.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *operation) {
    perror(operation);
    exit(1);
}

static void path_for(char *path, const char *base, const char *suffix) {
    int size = snprintf(path, PATH_MAX, "%s%s", base, suffix);
    if (size < 0 || size >= PATH_MAX) {
        errno = ENAMETOOLONG;
        fail("holder result path");
    }
}

static void write_text(const char *base, const char *suffix, const char *text) {
    char path[PATH_MAX], temporary[PATH_MAX];
    path_for(path, base, suffix);
    path_for(temporary, path, ".tmp");
    FILE *output = fopen(temporary, "w");
    if (!output) fail("open holder result");
    if (fputs(text, output) == EOF || fclose(output) != 0) fail("write holder result");
    if (rename(temporary, path) != 0) fail("publish holder result");
}

static double monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) fail("holder clock");
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
}

static void identity_json(char *identity, size_t capacity) {
    char stat[4096];
    FILE *input = fopen("/proc/self/stat", "r");
    if (!input) fail("open holder process identity");
    if (!fgets(stat, sizeof(stat), input)) fail("read holder process identity");
    if (fclose(input) != 0) fail("close holder process identity");
    char *tail = strrchr(stat, ')');
    char *field = tail ? strtok(tail + 1, " ") : NULL;
    for (int index = 0; field && index < 19; ++index) field = strtok(NULL, " ");
    if (!field || strspn(field, "0123456789") != strlen(field)) {
        fputs("invalid holder process start time\n", stderr);
        exit(1);
    }
    snprintf(identity, capacity, "{\"pid\":%ld,\"start\":\"%s\"}", (long)getpid(), field);
}

static void escape_json(char *output, const char *input) {
    for (const unsigned char *next = (const unsigned char *)input; *next; ++next) {
        if (*next < 32 || *next >= 127 || *next == '"' || *next == '\\') {
            output += sprintf(output, "\\u%04x", *next);
        } else {
            *output++ = (char)*next;
        }
    }
    *output = '\0';
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fputs("usage: mount-holder marker|file|cwd|mmap TARGET RESULT_BASE\n", stderr);
        return 2;
    }
    const char *mode = argv[1], *target = argv[2], *result = argv[3];
    int is_file = strcmp(mode, "file") == 0, is_cwd = strcmp(mode, "cwd") == 0;
    int is_mmap = strcmp(mode, "mmap") == 0;
    if (!is_file && !is_cwd && !is_mmap && strcmp(mode, "marker") != 0) {
        fputs("unknown holder mode\n", stderr);
        return 2;
    }
    int fd = -1;
    char *mapped = MAP_FAILED;
    if (is_file || is_mmap) {
        char path[PATH_MAX];
        path_for(path, target, "/host.txt");
        fd = open(path, O_RDWR);
        if (fd < 0) fail("open held file");
    } else if (is_cwd && chdir(target) != 0) {
        fail("enter held directory");
    }
    if (is_mmap) {
        struct stat info;
        if (fstat(fd, &info) != 0) fail("stat mapped file");
        if (info.st_size < 4096) {
            fputs("mapped fixture must contain at least 4096 bytes\n", stderr);
            return 1;
        }
        mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (mapped == MAP_FAILED) fail("map held file");
        if (close(fd) != 0) fail("close mapped descriptor");
        fd = -1; /* The busy mmap case must not also hold an open file. */
        char before[65] = {0};
        memcpy(before, mapped, 64);
        write_text(result, ".mapped-before", before);
    }
    char identity[160], release[PATH_MAX], heartbeat[64];
    identity_json(identity, sizeof(identity));
    path_for(release, result, ".release");
    double deadline = monotonic_seconds() + 300;
    snprintf(heartbeat, sizeof(heartbeat), "%.9f", monotonic_seconds());
    write_text(result, ".heartbeat", heartbeat);
    write_text(result, ".ready", identity);
    while (access(release, F_OK) != 0) {
        if (errno != ENOENT) fail("inspect holder release");
        if (monotonic_seconds() > deadline) {
            fputs("host did not release owned holder within 300 seconds\n", stderr);
            return 1;
        }
        snprintf(heartbeat, sizeof(heartbeat), "%.9f", monotonic_seconds());
        write_text(result, ".heartbeat", heartbeat);
        struct timespec delay = {0, 100000000};
        while (nanosleep(&delay, &delay) != 0) {
            if (errno != EINTR) fail("holder sleep");
        }
    }
    char data[65] = {0}, escaped[65 * 6], observation[1024];
    int error = 0;
    if (is_file) {
        if (pread(fd, data, 64, 0) < 0) error = errno;
    } else if (is_cwd) {
        fd = open("host.txt", O_RDONLY);
        if (fd < 0 || read(fd, data, 64) < 0) error = errno;
    } else if (is_mmap) {
        memcpy(data, mapped, 64);
    } else {
        strcpy(data, "marker survived");
    }
    escape_json(escaped, data);
    if (!error) {
        snprintf(observation, sizeof(observation), "{\"identity\":%s,\"data\":\"%s\"}", identity, escaped);
        /* Preserve a successful read even if the later mapped write signals SIGBUS. */
        write_text(result, ".read-result", observation);
        const char *written = "guest-open-handle-write";
        if (is_file) {
            if (pwrite(fd, written, strlen(written), 128) != (ssize_t)strlen(written)) error = errno ? errno : EIO;
        } else if (is_cwd) {
            int output = open("guest-cwd-write", O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (output < 0) error = errno;
            else {
                if (write(output, "guest-cwd-write", 15) != 15) error = errno ? errno : EIO;
                if (close(output) != 0 && !error) error = errno;
            }
        } else if (is_mmap) {
            memcpy(mapped + 128, written, strlen(written));
            if (msync(mapped, 4096, MS_SYNC) != 0) error = errno;
        }
    }
    snprintf(observation, sizeof(observation), "{\"identity\":%s,\"accessible\":%s,\"data\":\"%s\",\"errno\":%d}",
             identity, error ? "false" : "true", escaped, error);
    write_text(result, ".result", observation);
    if (error) { errno = error; perror("held access after release"); }
    if (mapped != MAP_FAILED && munmap(mapped, 4096) != 0) fail("unmap held file");
    if (fd >= 0 && close(fd) != 0) fail("close held file");
    return 0;
}
