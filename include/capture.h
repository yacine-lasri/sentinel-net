#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include "sentinelnet.h"

typedef void (*packet_cb_t)(void                     *ctx,
                            const packet_info_t      *info,
                            const struct pcap_pkthdr *hdr,
                            const uint8_t            *raw);

typedef struct {
    pcap_t      *handle;
    packet_cb_t  callback;
    void        *cb_ctx;
    volatile int running;
    char         errbuf[PCAP_ERRBUF_SIZE];
} capture_t;

capture_t *capture_init        (const char *iface,  const char *filter,
                                 packet_cb_t cb,     void *ctx);
capture_t *capture_init_offline(const char *path,   const char *filter,
                                 packet_cb_t cb,     void *ctx);
int        capture_start       (capture_t *cap);
void       capture_stop        (capture_t *cap);
void       capture_destroy     (capture_t *cap);
void       capture_list_interfaces(void);

#endif /* CAPTURE_H */
