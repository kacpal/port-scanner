#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>

#include "timer.h"
#include "synscan.h"
#include "scan_config.h"

#define SCAN_CONFIG_H_INCLUDED
#define	CHAR_BUFFER_LEN	64
#define MAX_PORT_NUM	65535


struct scan_config scan_opt;


void usage(char *name) {
	printf("Usage: %s <ip address> [options]\n", name);
	printf("Options:\n"
		"\t-p <port range>\n"
		"\t-h help\n"		);
	exit(1);
}

void scan_args(int argc, char *argv[]) {
	int opt;
	long port_num = 0;
	char char_buffer[CHAR_BUFFER_LEN], *char_ptr;

	while((opt = getopt(argc, argv, ":p:h")) != -1) {
		switch(opt) {
			case 'p':
				if (strlen(optarg) >= CHAR_BUFFER_LEN) {
					printf("Provided option is too long.\n");
					exit(-1);
				}
				strcpy(char_buffer, optarg);
				break;
			case 'h':
				usage(argv[0]);
				exit(0);
			default:
				usage(argv[0]);
				exit(-1);
		}
	}
	
	//when user provides port range:
	if (char_ptr = strchr(char_buffer, '-')) {
		long first_port, last_port;

		first_port = strtol(char_buffer, &char_ptr, 10);
		char_ptr++;
		last_port = strtol(char_ptr, NULL, 10);
		port_num = (last_port - first_port) + 1;

		if (port_num < 1 || first_port < 1 || last_port > MAX_PORT_NUM) {
			printf("Invalid port range.\n");
			usage(argv[0]);
			exit(-1);
		}
		scan_opt.first_port = first_port;
		scan_opt.last_port = last_port;
		scan_opt.port_num = port_num;

	//when user provided one port:
	} else {
		long port;

		port = strtol(char_buffer, NULL, 10);

		if (port < 0 || port > MAX_PORT_NUM) {
			printf("Invalid port number.\n");
			usage(argv[0]);
			exit(-1);
		}
		scan_opt.first_port = port;
		scan_opt.port_num = 1;
	}
}

int main(int argc, char *argv[]) {
	struct timespec program_start, program_end;
	double delta;
	int port;

	if (argc < 3)
		usage(argv[0]);

	scan_args(argc, argv);

	measure_time(&program_start, 0);

	/* perform the scan */
	if (syn_scan(argv[3]) == -1)
		exit(1);

	/* display scan time */
	if (measure_time(&program_end, 0) != -1) {
		printf("\nScan completed after %0.2fs.\n",
			calc_delta(&program_start, &program_end));
	}

	return 0;
}

