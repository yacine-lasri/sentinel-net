/*
 * main.c — SentinelNet entry point
 *
 * Usage:
 *   sudo ./sentinelnet <iface> [bpf-filter]
 *   sudo ./sentinelnet --file <path.pcap> [bpf-filter]
 *        ./sentinelnet --list
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "capture.h"
#include "detector.h"
#include "logger.h"
#include "parser.h"
#include "sentinelnet.h"
#include "stats.h"

#define JSON_DIR "/var/sentinelnet" /* where JSON files are written */
#define STATS_INTERVAL 5            /* write stats.json every N packets */
#define TRAFFIC_INTERVAL_SEC 1      /* write traffic.json every second  */

/* ── app state ────────────────────────────────────────────────── */
typedef struct {
  detector_t *det;
  stats_t *stats;
  logger_t *log;
  long pkt_count;

  /* per-second traffic counters */
  long sec_tcp;
  long sec_udp;
  long sec_icmp;
  time_t last_tick;
} app_t;

static capture_t *g_cap = NULL;
static app_t *g_app = NULL;

/* ── signal handler ───────────────────────────────────────────── */
static void on_sigint(int sig) {
  (void)sig;
  printf("\n[sentinelnet] shutting down...\n");
  if (g_cap)
    capture_stop(g_cap);
}

/* ── alert callback ───────────────────────────────────────────── */
static void on_alert(void *ctx, const alert_t *a) {
  app_t *app = (app_t *)ctx;
  logger_log(app->log, a);
}

/* ── packet callback ──────────────────────────────────────────── */
static void on_packet(void *ctx, const packet_info_t *info,
                      const struct pcap_pkthdr *hdr, const uint8_t *raw) {
  (void)hdr;
  (void)raw;
  app_t *app = (app_t *)ctx;

  app->pkt_count++;
  stats_update(app->stats, info);
  detector_feed(app->det, info);
  parser_print(info);

  /* per-second traffic counters */
  switch (info->proto) {
  case PROTO_TCP:
    app->sec_tcp++;
    break;
  case PROTO_UDP:
    app->sec_udp++;
    break;
  case PROTO_ICMP:
    app->sec_icmp++;
    break;
  default:
    break;
  }

  /* flush traffic.json once per second */
  time_t now = time(NULL);
  if (now - app->last_tick >= TRAFFIC_INTERVAL_SEC) {
    logger_write_traffic(app->log, app->sec_tcp, app->sec_udp, app->sec_icmp);
    app->sec_tcp = 0;
    app->sec_udp = 0;
    app->sec_icmp = 0;
    app->last_tick = now;
  }

  /* flush stats.json every N packets */
  if (app->pkt_count % STATS_INTERVAL == 0) {
    traffic_stats_t s;
    stats_get(app->stats, &s);
    logger_write_stats(app->log, &s);
  }
}

/* ── usage ────────────────────────────────────────────────────── */
static void usage(const char *prog) {
  fprintf(stderr,
          "SentinelNet — Network Intrusion Detection System\n\n"
          "Usage:\n"
          "  sudo %s <interface> [bpf-filter]   live capture\n"
          "  sudo %s --file <path> [bpf-filter] replay .pcap\n"
          "       %s --list                     list interfaces\n\n"
          "Examples:\n"
          "  sudo %s eth0\n"
          "  sudo %s eth0 \"tcp port 80\"\n"
          "  %s --file capture.pcap\n",
          prog, prog, prog, prog, prog, prog);
}

/* ── main ─────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
    return 1;
  }

  if (strcmp(argv[1], "--list") == 0) {
    capture_list_interfaces();
    return 0;
  }

  const char *iface = NULL;
  const char *file = NULL;
  const char *filter = NULL;
  int offline = 0;

  if (strcmp(argv[1], "--file") == 0) {
    if (argc < 3) {
      fprintf(stderr, "--file requires a path\n");
      return 1;
    }
    file = argv[2];
    filter = (argc >= 4) ? argv[3] : NULL;
    offline = 1;
  } else {
    iface = argv[1];
    filter = (argc >= 3) ? argv[2] : NULL;
  }

  /* ── init modules ─────────────────────────────────────────── */
  app_t app = {0};
  app.last_tick = time(NULL);

  app.log = logger_init("logs/alerts.log", "logs/stats.log", JSON_DIR,
                        SN_LOG_MAX_BYTES);
  app.stats = stats_init();
  app.det = detector_init(on_alert, &app);

  if (!app.log || !app.stats || !app.det) {
    fprintf(stderr, "[sentinelnet] failed to initialise modules\n");
    return 1;
  }

  /* ── init capture ─────────────────────────────────────────── */
  capture_t *cap = offline ? capture_init_offline(file, filter, on_packet, &app)
                           : capture_init(iface, filter, on_packet, &app);

  if (!cap) {
    fprintf(stderr, "[sentinelnet] capture init failed\n");
    logger_destroy(app.log);
    stats_destroy(app.stats);
    detector_destroy(app.det);
    return 1;
  }

  g_cap = cap;
  g_app = &app;
  signal(SIGINT, on_sigint);

  printf("[sentinelnet] started. alerts → logs/alerts.log\n");
  printf("[sentinelnet] JSON data → %s/\n", JSON_DIR);
  printf("[sentinelnet] press Ctrl+C to stop.\n\n");

  capture_start(cap);

  /* ── final stats flush on shutdown ───────────────────────── */
  traffic_stats_t s;
  stats_get(app.stats, &s);
  logger_write_stats(app.log, &s);

  printf("\n[sentinelnet] %ld packets captured\n", app.pkt_count);
  stats_print(app.stats);

  capture_destroy(cap);
  detector_destroy(app.det);
  stats_destroy(app.stats);
  logger_destroy(app.log);

  return 0;
}
