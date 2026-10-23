#ifndef DETECTOR_H
#define DETECTOR_H

/*
 * detector.h — Module 3: Detection Engine
 *
 * Rule-based detection for:
 *   - port scans     (one IP hitting many ports in a short window)
 *   - brute force    (one IP making many connections in a short window)
 *   - payload hits   (raw payload matching suspicious byte strings)
 */

#include "sentinelnet.h"

/* opaque detector state */
typedef struct detector detector_t;

/* callback fired when an alert is raised */
typedef void (*alert_cb_t)(void *ctx, const alert_t *alert);

/*
 * detector_init — allocate and return a new detector.
 *   cb  : function called when an alert fires
 *   ctx : forwarded to cb unchanged
 */
detector_t *detector_init(alert_cb_t cb, void *ctx);

/*
 * detector_feed — submit a parsed packet for analysis.
 * May call cb zero or more times before returning.
 */
void detector_feed(detector_t *det, const packet_info_t *info);

/*
 * detector_add_pattern — add a payload pattern to search for.
 *   pattern : null-terminated ASCII string, e.g. "/etc/passwd"
 * Returns 0 on success, -1 if the pattern table is full.
 */
int detector_add_pattern(detector_t *det, const char *pattern);

/*
 * detector_destroy — free all detector state.
 */
void detector_destroy(detector_t *det);

#endif /* DETECTOR_H */
