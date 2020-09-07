#ifndef SYNSCAN_H
#define SYNSCAN_H

#include "scan_config.h"
#include "synscan.h"
#include "timer.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void packet_listener(scan_opt_t *scan_opt);

int syn_scan(char *char_ipaddr, scan_opt_t *scan_opt);

#endif
