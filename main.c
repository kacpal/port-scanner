#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>

#include "timer.h"
#include "synscan.h"
#include "scan_config.h"

scan_opt_t scan_opt;

void usage(char *name) {
	printf("Usage: %s <ip address> [options]\n", name);
	printf("Options:\n"
		"\t-p <port range>\n"
		"\t-h Help\n"
		"\t-d Select the device\n"	 );
	exit(1);
}

void scan_args(int argc, char *argv[], scan_opt_t *scan_opt) {
	int opt;
	int port_num = 1;
	char char_buffer[CHAR_BUFFER_LEN] = "0", *char_ptr;

	while((opt = getopt(argc, argv, "p:hd:")) != -1) {
		switch(opt) {
			case 'p':
				if (strlen(optarg) >= CHAR_BUFFER_LEN) {
					printf("Provided option is too long.\n");
					exit(-1);
				}
				strncpy(char_buffer, optarg, strlen(optarg));
				break;
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'd':
				if (strlen(optarg) > DEVICE_NAME_LEN) {
					printf("Device name is too long.\n");
					exit(-1);
				}
				strncpy(scan_opt->device, optarg, strlen(optarg));
				break;
			default:
				usage(argv[0]);
				exit(-1);
				break;
		}
	}
	
	memset(scan_opt->port, 0, sizeof(int) * PORT_NUM);

	/* find occurance of the dash symbol */
	if (char_ptr = strchr(char_buffer, '-')) {
		int first_port, last_port;

		first_port = (int) strtol(char_buffer, &char_ptr, 10);
		char_ptr++;
		last_port = (int) strtol(char_ptr, NULL, 10);
		port_num = (last_port - first_port) + 1;

		/* safety sanitization */
		if (port_num < 1 || first_port < 1 || last_port >= PORT_NUM) {
			printf("Invalid port range.\n");
			usage(argv[0]);
			exit(-1);
		}

		/* set adresses that are meant to scan to 1 */
		for (int i=0; i < port_num; i++) {
			scan_opt->port[first_port + i] = 1;
		}
		scan_opt->port_num = port_num;

	/* if dash was not found */
	} else {
		int port;

		port = (int) strtol(char_buffer, NULL, 10);

		if (port < 1 || port >= PORT_NUM) {
			printf("Invalid port number.\n");
			usage(argv[0]);
			exit(-1);
		}

		scan_opt->port[port] = 1;
		scan_opt->port_num = 1;
	}

}

int main(int argc, char *argv[]) {
	struct timespec program_start, program_end;
	double delta;
	int port;
	char host[64];

	if (argc < 3)
		usage(argv[0]);

	strcpy(host, argv[1]);

	scan_args(argc, argv, &scan_opt);

	measure_time(&program_start, 0);

	/* perform the scan */
	if (syn_scan(host, &scan_opt) == -1)
		exit(1);

	/* display scan time */
	if (measure_time(&program_end, 0) != -1) {
		printf("\nScan completed after %0.2fs.\n",
			calc_delta(&program_start, &program_end));
	}

	return 0;
}

