#ifndef LOGGER_H
#define LOGGER_H

/*
 * logger.h — Module 5: Logging System
 *
 * Four outputs:
 *   1. logs/alerts.log  — human-readable timestamped alerts
 *   2. logs/stats.log   — human-readable traffic stats (per packet)
 *   3. Terminal         — coloured CLI output
 *   4. JSON files       — for the PHP web interface:
 *        /var/sentinelnet/alerts.json
 *        /var/sentinelnet/stats.json
 *        /var/sentinelnet/traffic.json
 */

#include "sentinelnet.h"

typedef struct logger logger_t;

/*
 * logger_init — open log files and prepare JSON output directory.
 *   alerts_path : alert log file e.g. "logs/alerts.log"
 *   stats_path  : stats log file  e.g. "logs/stats.log"
 *   json_dir    : directory for JSON files e.g. "/var/sentinelnet"
 *                 pass NULL to disable JSON output
 *   max_bytes   : rotate log files at this size (0 = never)
 */
logger_t *logger_init(const char *alerts_path,
                       const char *stats_path,
                       const char *json_dir,
                       long        max_bytes);

/* log an alert → appends to alerts.log, prints to CLI, rewrites alerts.json */
void logger_log(logger_t *log, const alert_t *a);

/*
 * logger_write_stats — append a stats snapshot to stats.log
 *                      and rewrite stats.json.
 * Call after every packet (or every N packets for performance).
 */
void logger_write_stats(logger_t *log, const traffic_stats_t *stats);

/* update traffic.json — call once per second with per-second counts */
void logger_write_traffic(logger_t *log, long tcp, long udp, long icmp);

void logger_destroy(logger_t *log);

#endif /* LOGGER_H */
