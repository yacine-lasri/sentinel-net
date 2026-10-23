/*
 * logger.c — Module 5: Logging System
 *
 * Writes to four destinations:
 *   1. logs/alerts.log   — human-readable timestamped alerts (with rotation)
 *   2. logs/stats.log    — human-readable traffic stats snapshot per packet
 *   3. stdout            — coloured terminal output
 *   4. /var/sentinelnet/ — JSON files for the PHP web interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "logger.h"

/* ── ANSI colours ─────────────────────────────────────────────── */
#define COL_RED     "\033[0;31m"
#define COL_YELLOW  "\033[0;33m"
#define COL_CYAN    "\033[0;36m"
#define COL_BOLD    "\033[1m"
#define COL_RESET   "\033[0m"

/* ── traffic history ring buffer (60 seconds) ─────────────────── */
#define TRAFFIC_HISTORY  60

typedef struct {
    char t[10];
    long tcp;
    long udp;
    long icmp;
} traffic_entry_t;

/* ── logger state ─────────────────────────────────────────────── */
struct logger {
    /* alert log file */
    FILE  *fp_alerts;
    char   alerts_path[256];

    /* stats log file — NEW */
    FILE  *fp_stats;
    char   stats_path[256];

    long   max_bytes;
    int    use_color;

    /* JSON output */
    char   json_dir[256];
    int    json_enabled;

    /* uptime tracking */
    time_t start_time;

    /* alerts list (in-memory, written to alerts.json) */
    char **alert_lines;
    int    alert_count;
    int    alert_cap;

    /* traffic ring buffer */
    traffic_entry_t history[TRAFFIC_HISTORY];
    int             history_count;
    int             history_head;
};

/* ── helpers ──────────────────────────────────────────────────── */

static void fmt_ts(const struct timeval *tv, char *buf, size_t len)
{
    struct tm tm;
    localtime_r(&tv->tv_sec, &tm);
    size_t n = strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
    snprintf(buf + n, len - n, ".%03ld", tv->tv_usec / 1000);
}

static void fmt_now(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
}

static const char *ip4str(uint32_t ip_net, char *buf)
{
    struct in_addr a = { .s_addr = ip_net };
    inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
    return buf;
}

static const char *alert_label(alert_type_t t)
{
    switch (t) {
        case ALERT_PORT_SCAN:   return "ALERT  ";
        case ALERT_BRUTE_FORCE: return "WARNING";
        case ALERT_PAYLOAD_HIT: return "ALERT  ";
        default:                return "INFO   ";
    }
}

static const char *alert_type_str(alert_type_t t)
{
    switch (t) {
        case ALERT_PORT_SCAN:   return "PORT_SCAN";
        case ALERT_BRUTE_FORCE: return "BRUTE_FORCE";
        case ALERT_PAYLOAD_HIT: return "PAYLOAD_HIT";
        default:                return "UNKNOWN";
    }
}

static const char *alert_color(alert_type_t t)
{
    switch (t) {
        case ALERT_PORT_SCAN:   return COL_RED;
        case ALERT_BRUTE_FORCE: return COL_YELLOW;
        case ALERT_PAYLOAD_HIT: return COL_RED;
        default:                return COL_CYAN;
    }
}

static void fmt_ports(const alert_t *a, char *buf, size_t len)
{
    size_t off = 0;
    for (int i = 0; i < a->port_count && off < len - 8; i++)
        off += (size_t)snprintf(buf + off, len - off,
                                i ? ",%d" : "%d", a->ports[i]);
}

/* ── atomic JSON write ────────────────────────────────────────── */

static void atomic_write(const char *path, const char *content)
{
    char tmp[300];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fputs(content, f);
    fclose(f);
    rename(tmp, path);
}

/* ── log rotation (shared helper) ────────────────────────────── */

static void maybe_rotate_fp(FILE **fp, const char *path, long max_bytes)
{
    if (!*fp || max_bytes <= 0) return;
    struct stat st;
    if (fstat(fileno(*fp), &st) == 0 && st.st_size >= max_bytes) {
        fclose(*fp);
        char backup[280];
        snprintf(backup, sizeof backup, "%s.1", path);
        rename(path, backup);
        *fp = fopen(path, "a");
        if (*fp)
            fprintf(*fp, "[logger] log rotated — previous: %s\n\n", backup);
    }
}

/* ── alert → alerts.log ───────────────────────────────────────── */

static void write_alert_file(struct logger *log, const alert_t *a,
                              const char *ts, const char *ip)
{
    if (!log->fp_alerts) return;

    fprintf(log->fp_alerts, "[%s] %s\n", ts, alert_label(a->type));

    switch (a->type) {
        case ALERT_PORT_SCAN: {
            char ports[512] = {0};
            fmt_ports(a, ports, sizeof ports);
            fprintf(log->fp_alerts,
                    "  Type   : Port scan\n"
                    "  Source : %s\n"
                    "  Ports  : %s\n\n", ip, ports);
            break;
        }
        case ALERT_BRUTE_FORCE:
            fprintf(log->fp_alerts,
                    "  Type   : Brute force attempt\n"
                    "  Source : %s\n"
                    "  Conns  : %d in %d seconds\n\n",
                    ip, a->conn_count, SN_BRUTEFORCE_WINDOW_SEC);
            break;
        case ALERT_PAYLOAD_HIT:
            fprintf(log->fp_alerts,
                    "  Type   : Suspicious payload\n"
                    "  Source : %s\n"
                    "  Pattern: \"%s\" at offset %d\n\n",
                    ip, a->pattern, a->payload_offset);
            break;
        default: break;
    }

    fflush(log->fp_alerts);
    maybe_rotate_fp(&log->fp_alerts, log->alerts_path, log->max_bytes);
}

/* ── stats snapshot → stats.log ──────────────────────────────── */

static void write_stats_file(struct logger *log,
                              const traffic_stats_t *stats)
{
    if (!log->fp_stats) return;

    char ts[32];
    fmt_now(ts, sizeof ts);
    long uptime = (long)(time(NULL) - log->start_time);

    fprintf(log->fp_stats,
            "[%s] Traffic Snapshot\n"
            "  Total   : %ld packets\n"
            "  TCP     : %ld\n"
            "  UDP     : %ld\n"
            "  ICMP    : %ld\n"
            "  Other   : %ld\n"
            "  Unique IPs : %ld\n"
            "  Uptime  : %lds\n\n",
            ts,
            stats->total,
            stats->tcp,
            stats->udp,
            stats->icmp,
            stats->other,
            stats->unique_ips,
            uptime);

    fflush(log->fp_stats);
    maybe_rotate_fp(&log->fp_stats, log->stats_path, log->max_bytes);
}

/* ── alert → CLI ──────────────────────────────────────────────── */

static void write_alert_cli(struct logger *log, const alert_t *a,
                             const char *ts, const char *ip)
{
    const char *col   = log->use_color ? alert_color(a->type) : "";
    const char *bold  = log->use_color ? COL_BOLD  : "";
    const char *reset = log->use_color ? COL_RESET : "";

    switch (a->type) {
        case ALERT_PORT_SCAN: {
            char ports[512] = {0};
            fmt_ports(a, ports, sizeof ports);
            printf("%s%s[%s] [ALERT] Port scan%s from %s — ports: %s\n",
                   bold, col, ts, reset, ip, ports);
            break;
        }
        case ALERT_BRUTE_FORCE:
            printf("%s%s[%s] [WARNING] Brute force%s from %s — "
                   "%d conns in %ds\n",
                   bold, col, ts, reset, ip,
                   a->conn_count, SN_BRUTEFORCE_WINDOW_SEC);
            break;
        case ALERT_PAYLOAD_HIT:
            printf("%s%s[%s] [ALERT] Payload hit%s from %s — "
                   "pattern \"%s\"\n",
                   bold, col, ts, reset, ip, a->pattern);
            break;
        default: break;
    }
    fflush(stdout);
}

/* ── alerts.json ──────────────────────────────────────────────── */

static void write_alerts_json(struct logger *log)
{
    if (!log->json_enabled) return;

    char path[300];
    snprintf(path, sizeof path, "%s/alerts.json", log->json_dir);

    size_t buf_sz = (size_t)(log->alert_count + 1) * 256 + 8;
    char  *buf    = malloc(buf_sz);
    if (!buf) return;

    size_t off = 0;
    off += (size_t)snprintf(buf + off, buf_sz - off, "[\n");
    for (int i = 0; i < log->alert_count; i++)
        off += (size_t)snprintf(buf + off, buf_sz - off,
                                "  %s%s\n", log->alert_lines[i],
                                i < log->alert_count - 1 ? "," : "");
    off += (size_t)snprintf(buf + off, buf_sz - off, "]\n");

    atomic_write(path, buf);
    free(buf);
}

static void store_alert(struct logger *log, const alert_t *a,
                         const char *ts, const char *ip)
{
    if (!log->json_enabled) return;

    if (log->alert_count >= log->alert_cap) {
        int new_cap = log->alert_cap == 0 ? 64 : log->alert_cap * 2;
        char **tmp = realloc(log->alert_lines,
                             (size_t)new_cap * sizeof(char *));
        if (!tmp) return;
        log->alert_lines = tmp;
        log->alert_cap   = new_cap;
    }

    char detail[256] = {0};
    switch (a->type) {
        case ALERT_PORT_SCAN: {
            char ports[200] = {0};
            fmt_ports(a, ports, sizeof ports);
            snprintf(detail, sizeof detail, "ports: %s", ports);
            break;
        }
        case ALERT_BRUTE_FORCE:
            snprintf(detail, sizeof detail,
                     "%d conns in %ds", a->conn_count,
                     SN_BRUTEFORCE_WINDOW_SEC);
            break;
        case ALERT_PAYLOAD_HIT:
            snprintf(detail, sizeof detail,
                     "pattern \\\"%s\\\"", a->pattern);
            break;
        default: break;
    }

    char *line = malloc(512);
    if (!line) return;

    char ts_short[20];
    strncpy(ts_short, ts, 19);
    ts_short[19] = '\0';

    snprintf(line, 512,
             "{\"time\":\"%s\",\"type\":\"%s\","
             "\"source_ip\":\"%s\",\"detail\":\"%s\"}",
             ts_short, alert_type_str(a->type), ip, detail);

    log->alert_lines[log->alert_count++] = line;
    write_alerts_json(log);
}

/* ── public API ───────────────────────────────────────────────── */

logger_t *logger_init(const char *alerts_path,
                       const char *stats_path,
                       const char *json_dir,
                       long        max_bytes)
{
    logger_t *log = calloc(1, sizeof *log);
    if (!log) { perror("calloc"); return NULL; }

    /* alerts log */
    if (alerts_path && alerts_path[0]) {
        strncpy(log->alerts_path, alerts_path, sizeof(log->alerts_path) - 1);
        log->fp_alerts = fopen(alerts_path, "a");
        if (!log->fp_alerts)
            fprintf(stderr, "[logger] cannot open %s\n", alerts_path);
    }

    /* stats log — NEW */
    if (stats_path && stats_path[0]) {
        strncpy(log->stats_path, stats_path, sizeof(log->stats_path) - 1);
        log->fp_stats = fopen(stats_path, "a");
        if (!log->fp_stats)
            fprintf(stderr, "[logger] cannot open %s\n", stats_path);
        else
            printf("[logger] stats log    → %s\n", stats_path);
    }

    log->max_bytes  = max_bytes;
    log->use_color  = isatty(STDOUT_FILENO);
    log->start_time = time(NULL);

    /* JSON output */
    if (json_dir && json_dir[0]) {
        mkdir(json_dir, 0755);
        strncpy(log->json_dir, json_dir, sizeof(log->json_dir) - 1);
        log->json_enabled = 1;

        char p[300];
        snprintf(p, sizeof p, "%s/alerts.json", json_dir);
        atomic_write(p, "[]\n");
        snprintf(p, sizeof p, "%s/stats.json", json_dir);
        atomic_write(p,
            "{\"total\":0,\"tcp\":0,\"udp\":0,\"icmp\":0,"
            "\"other\":0,\"unique_ips\":0,\"uptime_sec\":0}\n");
        snprintf(p, sizeof p, "%s/traffic.json", json_dir);
        atomic_write(p, "[]\n");

        printf("[logger] JSON output  → %s/\n", json_dir);
    }

    return log;
}

void logger_log(logger_t *log, const alert_t *a)
{
    if (!log || !a) return;

    char ts[32], ip[INET_ADDRSTRLEN];
    fmt_ts(&a->timestamp, ts, sizeof ts);
    ip4str(a->src_ip, ip);

    write_alert_file(log, a, ts, ip);
    write_alert_cli (log, a, ts, ip);
    store_alert(log, a, ts, ip);
}

void logger_write_stats(logger_t *log, const traffic_stats_t *stats)
{
    if (!log || !stats) return;

    /* always write to stats.log */
    write_stats_file(log, stats);

    /* update stats.json if JSON enabled */
    if (!log->json_enabled) return;

    char path[300];
    snprintf(path, sizeof path, "%s/stats.json", log->json_dir);

    long uptime = (long)(time(NULL) - log->start_time);

    char buf[512];
    snprintf(buf, sizeof buf,
             "{\n"
             "  \"total\":      %ld,\n"
             "  \"tcp\":        %ld,\n"
             "  \"udp\":        %ld,\n"
             "  \"icmp\":       %ld,\n"
             "  \"other\":      %ld,\n"
             "  \"unique_ips\": %ld,\n"
             "  \"uptime_sec\": %ld\n"
             "}\n",
             stats->total, stats->tcp, stats->udp,
             stats->icmp,  stats->other,
             stats->unique_ips, uptime);

    atomic_write(path, buf);
}

void logger_write_traffic(logger_t *log, long tcp, long udp, long icmp)
{
    if (!log || !log->json_enabled) return;

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char t[10];
    strftime(t, sizeof t, "%H:%M:%S", &tm);

    traffic_entry_t *slot = &log->history[log->history_head];
    snprintf(slot->t, sizeof slot->t, "%s", t);
    slot->tcp  = tcp;
    slot->udp  = udp;
    slot->icmp = icmp;

    log->history_head = (log->history_head + 1) % TRAFFIC_HISTORY;
    if (log->history_count < TRAFFIC_HISTORY)
        log->history_count++;

    char *buf = malloc((size_t)TRAFFIC_HISTORY * 80 + 8);
    if (!buf) return;

    size_t off = 0;
    off += (size_t)snprintf(buf + off, (size_t)TRAFFIC_HISTORY * 80, "[\n");

    int start = (log->history_count < TRAFFIC_HISTORY)
                ? 0 : log->history_head;

    for (int i = 0; i < log->history_count; i++) {
        int idx = (start + i) % TRAFFIC_HISTORY;
        traffic_entry_t *e = &log->history[idx];
        off += (size_t)snprintf(buf + off,
                                (size_t)TRAFFIC_HISTORY * 80 - off,
                                "  {\"t\":\"%s\","
                                "\"tcp\":%ld,"
                                "\"udp\":%ld,"
                                "\"icmp\":%ld}%s\n",
                                e->t, e->tcp, e->udp, e->icmp,
                                i < log->history_count - 1 ? "," : "");
    }

    snprintf(buf + off, 8, "]\n");

    char path[300];
    snprintf(path, sizeof path, "%s/traffic.json", log->json_dir);
    atomic_write(path, buf);
    free(buf);
}

void logger_destroy(logger_t *log)
{
    if (!log) return;
    if (log->fp_alerts) fclose(log->fp_alerts);
    if (log->fp_stats)  fclose(log->fp_stats);
    for (int i = 0; i < log->alert_count; i++)
        free(log->alert_lines[i]);
    free(log->alert_lines);
    free(log);
}
