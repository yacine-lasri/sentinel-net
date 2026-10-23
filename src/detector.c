/*
 * detector.c — Module 3: Detection Engine
 *
 * Implements three detectors:
 *
 *   1. Port scan    — one IP hits > SN_PORTSCAN_THRESHOLD unique ports
 *                     within SN_PORTSCAN_WINDOW_SEC seconds.
 *
 *   2. Brute force  — one IP makes > SN_BRUTEFORCE_THRESHOLD connections
 *                     within SN_BRUTEFORCE_WINDOW_SEC seconds.
 *
 *   3. Payload hit  — packet payload contains a registered pattern string.
 *
 * Per-IP state is stored in a simple open-addressing hash table keyed on
 * the 32-bit source IP.  Entries expire when their time window passes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "detector.h"
#include "sentinelnet.h"

/* ── tuning ───────────────────────────────────────────────────── */
#define IP_TABLE_SIZE   1024    /* must be power of two             */
#define MAX_PATTERNS      64

/* ── per-IP tracking entry ────────────────────────────────────── */
typedef struct {
    uint32_t ip;
    int      occupied;

    /* port scan */
    uint16_t ports[SN_MAX_PORTS];
    int      port_count;
    time_t   ps_window_start;
    int      ps_alerted;        /* suppress duplicate alerts        */

    /* brute force */
    int      conn_count;
    time_t   bf_window_start;
    int      bf_alerted;
} ip_entry_t;

/* ── detector state ───────────────────────────────────────────── */
struct detector {
    ip_entry_t  table[IP_TABLE_SIZE];

    char        patterns[MAX_PATTERNS][64];
    int         pattern_count;

    alert_cb_t  cb;
    void       *cb_ctx;
};

/* ── hash table helpers ───────────────────────────────────────── */

static ip_entry_t *ip_find_or_create(detector_t *det, uint32_t ip)
{
    uint32_t idx = (ip ^ (ip >> 16)) & (IP_TABLE_SIZE - 1);

    for (int i = 0; i < IP_TABLE_SIZE; i++) {
        ip_entry_t *e = &det->table[(idx + i) & (IP_TABLE_SIZE - 1)];
        if (!e->occupied) {
            /* empty slot — initialise */
            memset(e, 0, sizeof *e);
            e->ip       = ip;
            e->occupied = 1;
            return e;
        }
        if (e->ip == ip)
            return e;
    }
    return NULL;   /* table full — very unlikely at 1024 entries */
}

/* ── port scan detector ───────────────────────────────────────── */

static void check_port_scan(detector_t *det, ip_entry_t *e,
                             uint16_t dst_port, struct timeval ts)
{
    time_t now = ts.tv_sec;

    /* reset window if expired */
    if (now - e->ps_window_start > SN_PORTSCAN_WINDOW_SEC) {
        e->port_count    = 0;
        e->ps_window_start = now;
        e->ps_alerted    = 0;
    }

    if (e->ps_alerted) return;

    /* record port if not already seen */
    int seen = 0;
    for (int i = 0; i < e->port_count; i++)
        if (e->ports[i] == dst_port) { seen = 1; break; }

    if (!seen && e->port_count < SN_MAX_PORTS)
        e->ports[e->port_count++] = dst_port;

    if (e->port_count >= SN_PORTSCAN_THRESHOLD) {
        alert_t a;
        memset(&a, 0, sizeof a);
        a.type      = ALERT_PORT_SCAN;
        a.timestamp = ts;
        a.src_ip    = e->ip;
        a.port_count = e->port_count;
        memcpy(a.ports, e->ports,
               (size_t)e->port_count * sizeof(uint16_t));
        e->ps_alerted = 1;
        det->cb(det->cb_ctx, &a);
    }
}

/* ── brute force detector ─────────────────────────────────────── */

static void check_brute_force(detector_t *det, ip_entry_t *e,
                               struct timeval ts)
{
    time_t now = ts.tv_sec;

    if (now - e->bf_window_start > SN_BRUTEFORCE_WINDOW_SEC) {
        e->conn_count      = 0;
        e->bf_window_start = now;
        e->bf_alerted      = 0;
    }

    if (e->bf_alerted) return;

    e->conn_count++;

    if (e->conn_count >= SN_BRUTEFORCE_THRESHOLD) {
        alert_t a;
        memset(&a, 0, sizeof a);
        a.type       = ALERT_BRUTE_FORCE;
        a.timestamp  = ts;
        a.src_ip     = e->ip;
        a.conn_count = e->conn_count;
        e->bf_alerted = 1;
        det->cb(det->cb_ctx, &a);
    }
}

/* ── payload detector ─────────────────────────────────────────── */

static void check_payload(detector_t *det, const packet_info_t *info)
{
    if (!info->payload || info->payload_len == 0) return;

    for (int i = 0; i < det->pattern_count; i++) {
        const char   *pat    = det->patterns[i];
        size_t        patlen = strlen(pat);
        const uint8_t *p     = info->payload;
        uint32_t       rem   = info->payload_len;

        while (rem >= patlen) {
            if (memcmp(p, pat, patlen) == 0) {
                alert_t a;
                memset(&a, 0, sizeof a);
                a.type           = ALERT_PAYLOAD_HIT;
                a.timestamp      = info->ts;
                a.src_ip         = info->src_ip;
                a.payload_offset = (int)(p - info->payload);
                strncpy(a.pattern, pat, sizeof a.pattern - 1);
                det->cb(det->cb_ctx, &a);
                return;   /* one alert per packet per pattern */
            }
            p++;
            rem--;
        }
    }
}

/* ── public API ───────────────────────────────────────────────── */

detector_t *detector_init(alert_cb_t cb, void *ctx)
{
    detector_t *det = calloc(1, sizeof *det);
    if (!det) { perror("calloc"); return NULL; }
    det->cb     = cb;
    det->cb_ctx = ctx;

    /* default payload patterns */
    detector_add_pattern(det, "/etc/passwd");
    detector_add_pattern(det, "/etc/shadow");
    detector_add_pattern(det, "cmd.exe");
    detector_add_pattern(det, "nmap");
    detector_add_pattern(det, "../");        /* path traversal       */
    detector_add_pattern(det, "SELECT ");    /* SQLi probe           */
    detector_add_pattern(det, "<script");    /* XSS probe            */

    return det;
}

void detector_feed(detector_t *det, const packet_info_t *info)
{
    if (!det || !info) return;

    ip_entry_t *e = ip_find_or_create(det, info->src_ip);
    if (!e) return;

    /* port scan — trigger on TCP SYN to varied destination ports */
    if (info->proto == PROTO_TCP && info->dst_port)
        check_port_scan(det, e, info->dst_port, info->ts);

    /* brute force — trigger on any TCP/UDP connection attempt */
    if (info->proto == PROTO_TCP || info->proto == PROTO_UDP)
        check_brute_force(det, e, info->ts);

    /* payload matching */
    check_payload(det, info);
}

int detector_add_pattern(detector_t *det, const char *pattern)
{
    if (det->pattern_count >= MAX_PATTERNS) return -1;
    strncpy(det->patterns[det->pattern_count], pattern, 63);
    det->patterns[det->pattern_count][63] = '\0';
    det->pattern_count++;
    return 0;
}

void detector_destroy(detector_t *det)
{
    free(det);
}
