/* Read-only allocator/RSS observer, loaded into the disposable test proxy. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static void *observe(void *argument) {
    int output = *(int *)argument;
    for (;;) {
        struct mallinfo2 heap = mallinfo2();
        struct timespec at;
        clock_gettime(CLOCK_MONOTONIC, &at);
        char status[128] = {0}, row[512];
        unsigned long pages = 0, resident = 0;
        int input = open("/proc/self/statm", O_RDONLY);
        if (input < 0) return NULL;
        ssize_t size = read(input, status, sizeof(status) - 1);
        close(input);
        if (size <= 0 || sscanf(status, "%lu %lu", &pages, &resident) != 2) return NULL;
        int length = snprintf(row, sizeof(row),
            "{\"pid\":%d,\"at\":%.6f,\"arena\":%zu,\"allocated\":%zu,\"free\":%zu,\"rss_kib\":%lu}\n",
            getpid(), at.tv_sec + at.tv_nsec / 1e9, heap.arena,
            heap.uordblks + heap.hblkhd, heap.fordblks,
            resident * (unsigned long)sysconf(_SC_PAGESIZE) / 1024);
        if (write(output, row, length) != length) return NULL;
        usleep(250000);
    }
}

__attribute__((constructor)) static void start_observer(void) {
    const char *path = getenv("SAFEYOLO_HEAP_SAMPLE_PATH");
    if (!path) return;
    static int output;
    output = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (output < 0) return;
    pthread_t thread;
    if (pthread_create(&thread, NULL, observe, &output) == 0) pthread_detach(thread);
}
