/* Child-only libpcap control: a valid idle source followed by a read error. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *pcap_create(const char *device, char *error) {
    (void)device;
    (void)error;
    return malloc(1);
}
void pcap_close(void *handle) { free(handle); }

#define SETTER(name) \
    int name(void *handle, int value) { \
        (void)handle; \
        (void)value; \
        return 0; \
    }
SETTER(pcap_set_snaplen)
SETTER(pcap_set_promisc)
SETTER(pcap_set_timeout)
SETTER(pcap_set_buffer_size)
SETTER(pcap_set_immediate_mode)
SETTER(pcap_set_tstamp_precision)

int pcap_activate(void *handle) { (void)handle; return 0; }
int pcap_get_tstamp_precision(void *handle) { (void)handle; return 0; }
int pcap_datalink(void *handle) { (void)handle; return 1; }
int pcap_compile(void *handle, void *program, const char *filter, int optimize,
                 uint32_t netmask) {
    (void)handle; (void)program; (void)filter; (void)optimize; (void)netmask;
    return 0;
}
int pcap_setfilter(void *handle, void *program) {
    (void)handle; (void)program; return 0;
}
void pcap_freecode(void *program) { (void)program; }
int pcap_setnonblock(void *handle, int nonblock, char *error) {
    (void)handle; (void)nonblock; (void)error; return 0;
}
int pcap_next_ex(void *handle, const void **header, const unsigned char **data) {
    (void)handle; (void)header; (void)data;
    const char *trigger = getenv("SAFEYOLO_WIRE_SOURCE_FAULT");
    return trigger && access(trigger, F_OK) == 0 ? -1 : 0;
}
int pcap_stats(void *handle, uint32_t *stats) {
    (void)handle;
    memset(stats, 0, 3 * sizeof(*stats));
    return 0;
}
