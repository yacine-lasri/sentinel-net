/*
 * capture.c — Module 1: Packet Capture
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capture.h"
#include "parser.h"

static void sn_pcap_handler(u_char *user, const struct pcap_pkthdr *hdr,
                         const u_char *bytes)
{
    capture_t    *cap = (capture_t *)user;
    packet_info_t info;
    if (!cap->running) return;
    if (parser_parse(hdr, bytes, &info))
        cap->callback(cap->cb_ctx, &info, hdr, bytes);
}

static capture_t *alloc_cap(packet_cb_t cb, void *ctx)
{
    capture_t *cap = calloc(1, sizeof *cap);
    if (!cap) { perror("calloc"); return NULL; }
    cap->callback = cb;
    cap->cb_ctx   = ctx;
    cap->running  = 1;
    return cap;
}

static int apply_filter(capture_t *cap, const char *filter)
{
    if (!filter || !filter[0]) return 0;
    struct bpf_program fp;
    if (pcap_compile(cap->handle, &fp, filter, 1, 0) == -1) {
        fprintf(stderr, "[capture] BPF compile: %s\n", pcap_geterr(cap->handle));
        return -1;
    }
    if (pcap_setfilter(cap->handle, &fp) == -1) {
        fprintf(stderr, "[capture] BPF setfilter: %s\n", pcap_geterr(cap->handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    return 0;
}

capture_t *capture_init(const char *iface, const char *filter,
                        packet_cb_t cb, void *ctx)
{
    capture_t *cap = alloc_cap(cb, ctx);
    if (!cap) return NULL;
    cap->handle = pcap_open_live(iface, SN_SNAPLEN, SN_PROMISC,
                                 SN_TIMEOUT_MS, cap->errbuf);
    if (!cap->handle) {
        fprintf(stderr, "[capture] pcap_open_live(%s): %s\n", iface, cap->errbuf);
        free(cap); return NULL;
    }
    if (cap->errbuf[0]) fprintf(stderr, "[capture] warning: %s\n", cap->errbuf);
    if (pcap_datalink(cap->handle) != DLT_EN10MB) {
        fprintf(stderr, "[capture] only Ethernet (DLT_EN10MB) supported\n");
        pcap_close(cap->handle); free(cap); return NULL;
    }
    if (apply_filter(cap, filter) == -1) {
        pcap_close(cap->handle); free(cap); return NULL;
    }
    printf("[capture] listening on %s (snaplen=%d promisc=%d)\n",
           iface, SN_SNAPLEN, SN_PROMISC);
    if (filter) printf("[capture] filter: %s\n", filter);
    return cap;
}

capture_t *capture_init_offline(const char *path, const char *filter,
                                 packet_cb_t cb, void *ctx)
{
    capture_t *cap = alloc_cap(cb, ctx);
    if (!cap) return NULL;
    cap->handle = pcap_open_offline(path, cap->errbuf);
    if (!cap->handle) {
        fprintf(stderr, "[capture] pcap_open_offline(%s): %s\n", path, cap->errbuf);
        free(cap); return NULL;
    }
    if (apply_filter(cap, filter) == -1) {
        pcap_close(cap->handle); free(cap); return NULL;
    }
    printf("[capture] replaying: %s\n", path);
    return cap;
}

int capture_start(capture_t *cap)
{
    int ret = pcap_loop(cap->handle, -1, sn_pcap_handler, (u_char *)cap);
    if (ret == PCAP_ERROR_BREAK) return 0;
    if (ret == PCAP_ERROR) {
        fprintf(stderr, "[capture] pcap_loop: %s\n", pcap_geterr(cap->handle));
        return -1;
    }
    return 0;
}

void capture_stop(capture_t *cap)
{
    if (!cap) return;
    cap->running = 0;
    pcap_breakloop(cap->handle);
}

void capture_destroy(capture_t *cap)
{
    if (!cap) return;
    if (cap->handle) pcap_close(cap->handle);
    free(cap);
}

void capture_list_interfaces(void)
{
    pcap_if_t *devs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devs, errbuf) == -1) {
        fprintf(stderr, "[capture] findalldevs: %s\n", errbuf);
        return;
    }
    printf("Available interfaces:\n");
    int i = 1;
    for (d = devs; d; d = d->next) {
        printf("  %d. %-16s", i++, d->name);
        if (d->description) printf("  %s", d->description);
        printf("\n");
    }
    pcap_freealldevs(devs);
}
