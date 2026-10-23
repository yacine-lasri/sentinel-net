#ifndef SENTINELNET_H
#define SENTINELNET_H

#include <stdint.h>
#include <sys/time.h>

/* ── tunables ─────────────────────────────────────────────────── */
#define SN_SNAPLEN           65535
#define SN_PROMISC           1
#define SN_TIMEOUT_MS        1000
#define SN_MAX_PORTS         128
#define SN_LOG_MAX_BYTES     (10 * 1024 * 1024)   /* 10 MB rotation  */

#define SN_PORTSCAN_THRESHOLD   15    /* unique ports in window       */
#define SN_PORTSCAN_WINDOW_SEC   5
#define SN_BRUTEFORCE_THRESHOLD 100   /* connections in window        */
#define SN_BRUTEFORCE_WINDOW_SEC 10

/* ── protocol numbers ─────────────────────────────────────────── */
#define PROTO_ICMP   1
#define PROTO_TCP    6
#define PROTO_UDP   17

/* ── parsed packet ────────────────────────────────────────────── */
typedef struct {
    struct timeval  ts;
    uint32_t        src_ip;       /* network byte order             */
    uint32_t        dst_ip;
    uint8_t         proto;
    uint16_t        src_port;     /* host byte order                */
    uint16_t        dst_port;
    uint32_t        pkt_len;
    const uint8_t  *payload;
    uint32_t        payload_len;
} packet_info_t;

/* ── alert ────────────────────────────────────────────────────── */
typedef enum {
    ALERT_PORT_SCAN   = 0,
    ALERT_BRUTE_FORCE,
    ALERT_PAYLOAD_HIT
} alert_type_t;

typedef struct {
    alert_type_t    type;
    struct timeval  timestamp;
    uint32_t        src_ip;
    uint16_t        ports[SN_MAX_PORTS];
    int             port_count;
    int             conn_count;
    char            pattern[64];
    int             payload_offset;
} alert_t;

/* ── traffic statistics ───────────────────────────────────────── */
typedef struct {
    long total;
    long tcp;
    long udp;
    long icmp;
    long other;
    long unique_ips;
} traffic_stats_t;

#endif /* SENTINELNET_H */
