#ifndef STATS_H
#define STATS_H

/*
 * stats.h — Module 4: Traffic Statistics
 *
 * Maintains per-protocol packet counters and a unique-IP set.
 */

#include "sentinelnet.h"

typedef struct stats stats_t;

stats_t *stats_init   (void);
void     stats_update (stats_t *s, const packet_info_t *info);
void     stats_print  (const stats_t *s);
void     stats_get    (const stats_t *s, traffic_stats_t *out);
void     stats_destroy(stats_t *s);

#endif /* STATS_H */
