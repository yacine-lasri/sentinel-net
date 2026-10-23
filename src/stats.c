/*
 * stats.c — Module 4: Traffic Statistics
 *
 * Maintains per-protocol packet counters and a lightweight unique-IP
 * hash set so we can report how many distinct hosts we've seen.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"

/* ── unique-IP hash set ───────────────────────────────────────── */
#define IP_SET_SIZE  4096   /* power of two; collision via linear probe */

typedef struct {
    uint32_t ip;
    int      used;
} ip_slot_t;

struct stats {
    long      total;
    long      tcp;
    long      udp;
    long      icmp;
    long      other;

    ip_slot_t ip_set[IP_SET_SIZE];
    long      unique_ips;
};

static void ip_set_insert(struct stats *s, uint32_t ip)
{
    uint32_t idx = (ip ^ (ip >> 16)) & (IP_SET_SIZE - 1);
    for (int i = 0; i < IP_SET_SIZE; i++) {
        ip_slot_t *slot = &s->ip_set[(idx + i) & (IP_SET_SIZE - 1)];
        if (!slot->used) {
            slot->ip   = ip;
            slot->used = 1;
            s->unique_ips++;
            return;
        }
        if (slot->ip == ip) return;   /* already counted */
    }
    /* set full — don't count (extremely unlikely) */
}

/* ── public API ───────────────────────────────────────────────── */

stats_t *stats_init(void)
{
    stats_t *s = calloc(1, sizeof *s);
    if (!s) perror("calloc");
    return s;
}

void stats_update(stats_t *s, const packet_info_t *info)
{
    if (!s || !info) return;
    s->total++;
    switch (info->proto) {
        case PROTO_TCP:  s->tcp++;  break;
        case PROTO_UDP:  s->udp++;  break;
        case PROTO_ICMP: s->icmp++; break;
        default:         s->other++; break;
    }
    ip_set_insert(s, info->src_ip);
    ip_set_insert(s, info->dst_ip);
}

void stats_print(const stats_t *s)
{
    if (!s) return;
    printf("\n── Traffic Summary ───────────────────────\n");
    printf("  Total packets : %ld\n", s->total);
    printf("  TCP           : %ld\n", s->tcp);
    printf("  UDP           : %ld\n", s->udp);
    printf("  ICMP          : %ld\n", s->icmp);
    printf("  Other         : %ld\n", s->other);
    printf("  Unique hosts  : %ld\n", s->unique_ips);
    printf("──────────────────────────────────────────\n\n");
}

void stats_get(const stats_t *s, traffic_stats_t *out)
{
    if (!s || !out) return;
    out->total      = s->total;
    out->tcp        = s->tcp;
    out->udp        = s->udp;
    out->icmp       = s->icmp;
    out->other      = s->other;
    out->unique_ips = s->unique_ips;
}

void stats_destroy(stats_t *s)
{
    free(s);
}
