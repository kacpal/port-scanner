#include <stdlib.h>
#include <libnet.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <stdbool.h>

#include "timer.h"
#include "synscan.h"
#include "scan_config.h"


int answer;				//scan flag
struct timespec scan_start, scan_end;
double delta;
pcap_t *handle;				//pcap handle

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* convert arguments from required u_char to typedef scan_opt_t */
	scan_opt_t *scan_opt = (scan_opt_t *) args;

	struct tcphdr *tcp = (struct tcphdr *) (packet + LIBNET_IPV4_H + LIBNET_ETH_H); 
	int port = ntohs(tcp->th_sport);
	
	if (tcp->th_flags == 0x14) {
		printf("%d\tclosed\n", port);
		scan_opt->port[port] = 0;
		answer--;
	} else if (tcp->th_flags == 0x12) {
		printf("%d\topened\n", port);
		scan_opt->port[port] = 0;
		answer--;
	}
}

void packet_listener(scan_opt_t *scan_opt) {

	while (answer) {
		pcap_dispatch(handle, -1, packet_handler, (u_char *)scan_opt);

		measure_time(&scan_end, 1);
		delta = calc_delta(&scan_start, &scan_end);

		/* after 2s set the port status to filtered */
		if (delta > 2.0) {
			for (int i=0; i < PORT_NUM; i++) {
				if (scan_opt->port[i] == 1)
					printf("%d\tfiltered\n", i);
				answer = 0;
			}
		}
	}
}

int syn_scan(char *char_ipaddr, scan_opt_t *scan_opt) {

	const char *device = scan_opt->device;
	in_addr_t ipaddr;			//target IP address
	u_int32_t my_ipaddr;			//host IP address
	libnet_t *l;				//libnet context
	char libnet_errbuf[LIBNET_ERRBUF_SIZE];	//libnet error buffer
	char pcap_errbuf[PCAP_ERRBUF_SIZE];	//pcap error buffer
	char *filter =
		"(tcp[13] == 0x14) || (tcp[13] == 0x12)";	//(SYN and RST) or ACK flags are set
       	bpf_u_int32 netp, maskp;		//netmask and IP
	struct bpf_program fp;			//compiled filter	
	libnet_ptag_t tcp = 0, ipv4 = 0;	//libnet protocol blocks
	int port;

	/* libnet initial setup */
	l = libnet_init(LIBNET_RAW4, device, libnet_errbuf);
	if (l == NULL) {
		fprintf(stderr, "Unable to open context: %s", libnet_errbuf);
		printf("Try running this program as root.\n");
		return -1;
	}
	
	ipaddr = libnet_name2addr4(l, char_ipaddr, LIBNET_RESOLVE);
	if (ipaddr == -1) {
		fprintf(stderr, "Invalid address: %s\n", libnet_geterror(l));
		return -1;
	}

	my_ipaddr = libnet_get_ipaddr4(l);
	if (my_ipaddr == -1) {
		fprintf(stderr, "Unable to get the host IP: %s", libnet_geterror(l));
		printf("Try selecting the device manually with '-d'.\n");
		return -1;
	}

	/* pcap initial setup */
	device = libnet_getdevice(l);
	if (device == NULL) {
		fprintf(stderr, "Warning: NULL device.\n");
	}

	handle = pcap_open_live(device, 1500, 0, 100, pcap_errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Unable to open the device: %s\n", pcap_errbuf);
		return -1;
	}
	if ((pcap_setnonblock (handle, 1, libnet_errbuf)) == -1) {
    		fprintf(stderr, "Error setting nonblocking: %s\n", pcap_errbuf);
    		return -1;
    	}

	/* set the capture filter */
	if (pcap_lookupnet(device, &netp, &maskp, pcap_errbuf) == -1) {
		fprintf(stderr, "Net lookup error: %s\n", pcap_errbuf);
		return -1;
	}
	if (pcap_compile (handle, &fp, filter, 0, maskp) == -1) {
		fprintf(stderr, "BPF error: %s\n", pcap_geterr(handle));
     		return -1;
	}
 	if (pcap_setfilter (handle, &fp) == -1) {
      		fprintf(stderr, "Error setting BPF: %s\n", pcap_geterr(handle));
     		return -1;
	}

	pcap_freecode(&fp);

	libnet_seed_prand(l);

	for (int i=0; i < PORT_NUM; i++) {
		if (scan_opt->port[i] == 1) {
			port = i;

			/* build TCP and IP headers */
			tcp = libnet_build_tcp(libnet_get_prand(LIBNET_PRu16),	//src port
					port,					//destination port
					libnet_get_prand(LIBNET_PRu16),		//sequence number
					0,					//acknowledgement
					TH_SYN,					//control flag
					7,					//window
					0,					//checksum
					0,					//urgent
					LIBNET_TCP_H,				//header length
					NULL,					//payload
					0,					//payload length
					l,					//libnet context
					tcp);					//protocol tag

			if (tcp == -1) {
				fprintf(stderr, "Unable to build TCP header: %s\n", libnet_geterror(l));
				return -1;
			}

			ipv4 = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H,	//length
					0,					//TOS	
					libnet_get_prand(LIBNET_PRu16),		//IP ID
					0,					//frag offset
					127,					//TTL
					IPPROTO_TCP,				//upper layer protocol
					0,					//checksum
					my_ipaddr,				//src IP
					ipaddr,					//dest IP
					NULL,					//payload
					0,					//payload length
					l,					//libnet context
					ipv4);					//protocol tag
			
			if (ipv4 == -1) {
				fprintf(stderr, "Unable to build IPv4 header: %s\n", libnet_geterror(l));
				return -1;
			}


			/* send the packet */
			if (libnet_write(l) == -1) {
				fprintf(stderr, "Unable to send packet: %s\n", libnet_geterror(l));
				return -1;
			}
		}
	}


	measure_time(&scan_start, 1);

	printf("======================\n"
			"PORT\tSTATE\n"
			"======================\n");

	answer = scan_opt->port_num;
	packet_listener(scan_opt);
	
	libnet_destroy(l);
	return 0;
}
