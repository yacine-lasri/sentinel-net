/*
 * parser.c — Module 2: Protocol Parser
 *
 * Dissects raw Ethernet/IPv4/TCP/UDP/ICMP bytes into packet_info_t.
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "parser.h"
#include "sentinelnet.h"

/* ── helpers ──────────────────────────────────────────────────── */

static const char *proto_name(uint8_t p)
{
    switch (p) {
        case PROTO_TCP:  return "TCP";
        case PROTO_UDP:  return "UDP";
        case PROTO_ICMP: return "ICMP";
        default:         return "???";
    }
}

static const char *ip4str(uint32_t ip_net, char *buf)
{
    struct in_addr a = { .s_addr = ip_net };
    inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
    return buf;
}

/* ── public API ───────────────────────────────────────────────── */

int parser_parse(const struct pcap_pkthdr *hdr,
                 const uint8_t            *bytes,
                 packet_info_t            *out)
{
    memset(out, 0, sizeof *out);
    out->ts      = hdr->ts;
    out->pkt_len = hdr->len;

    /* ── Layer 2: Ethernet ──────────────────────────────────── */
    if (hdr->caplen < sizeof(struct ether_header))
        return 0;

    const struct ether_header *eth = (const struct ether_header *)bytes;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return 0;   /* skip ARP, IPv6, VLAN, etc. */

    /* ── Layer 3: IPv4 ──────────────────────────────────────── */
    size_t ip_off = sizeof(struct ether_header);   /* always 14 bytes */
    if (hdr->caplen < ip_off + sizeof(struct ip))
        return 0;

    const struct ip *iph = (const struct ip *)(bytes + ip_off);
    size_t ip_hdr_len    = (size_t)iph->ip_hl * 4;

    if (ip_hdr_len < 20)   /* RFC 791 minimum */
        return 0;

    out->src_ip = iph->ip_src.s_addr;   /* keep in network byte order */
    out->dst_ip = iph->ip_dst.s_addr;
    out->proto  = iph->ip_p;

    size_t xport_off = ip_off + ip_hdr_len;

    /* ── Layer 4: TCP / UDP / ICMP ──────────────────────────── */
    switch (iph->ip_p) {

        case PROTO_TCP: {
            if (hdr->caplen < xport_off + sizeof(struct tcphdr))
                return 0;
            const struct tcphdr *tcp =
                (const struct tcphdr *)(bytes + xport_off);
            out->src_port = ntohs(tcp->th_sport);
            out->dst_port = ntohs(tcp->th_dport);
            size_t th_len  = (size_t)tcp->th_off * 4;
            size_t pay_off = xport_off + th_len;
            if (pay_off < hdr->caplen) {
                out->payload     = bytes + pay_off;
                out->payload_len = hdr->caplen - (uint32_t)pay_off;
            }
            break;
        }

        case PROTO_UDP: {
            if (hdr->caplen < xport_off + sizeof(struct udphdr))
                return 0;
            const struct udphdr *udp =
                (const struct udphdr *)(bytes + xport_off);
            out->src_port = ntohs(udp->uh_sport);
            out->dst_port = ntohs(udp->uh_dport);
            size_t pay_off = xport_off + sizeof(struct udphdr);
            if (pay_off < hdr->caplen) {
                out->payload     = bytes + pay_off;
                out->payload_len = hdr->caplen - (uint32_t)pay_off;
            }
            break;
        }

        case PROTO_ICMP: {
            /* ICMP header is 8 bytes; no ports */
            size_t pay_off = xport_off + 8;
            if (pay_off < hdr->caplen) {
                out->payload     = bytes + pay_off;
                out->payload_len = hdr->caplen - (uint32_t)pay_off;
            }
            break;
        }

        default:
            break;   /* forward with zero ports */
    }

    return 1;
}

void parser_print(const packet_info_t *info)
{
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip4str(info->src_ip, src);
    ip4str(info->dst_ip, dst);

    if (info->src_port || info->dst_port)
        printf("%-4s  %s:%-5u  →  %s:%-5u  (%u bytes)\n",
               proto_name(info->proto),
               src, info->src_port,
               dst, info->dst_port,
               info->pkt_len);
    else
        printf("%-4s  %s  →  %s  (%u bytes)\n",
               proto_name(info->proto), src, dst, info->pkt_len);
}
