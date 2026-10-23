#ifndef PARSER_H
#define PARSER_H

/*
 * parser.h — Module 2: Protocol Parser
 *
 * Parses raw libpcap bytes into a clean packet_info_t.
 * Called internally by capture.c; also usable standalone for tests.
 */

#include <pcap.h>
#include "sentinelnet.h"

/*
 * parser_parse — dissect one raw packet.
 * Returns 1 on success, 0 if the packet should be discarded.
 */
int parser_parse(const struct pcap_pkthdr *hdr,
                 const uint8_t            *bytes,
                 packet_info_t            *out);

/*
 * parser_print — print a one-line summary of a parsed packet to stdout.
 */
void parser_print(const packet_info_t *info);

#endif /* PARSER_H */
