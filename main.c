#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include <getopt.h>

#include "timer.h"
#include "synscan.h"

void usage(char *name);

int main(int argc, char *argv[]) 
{
	struct timespec program_start, program_end;
	double delta;
	int port;

	if (argc < 3)
		usage(argv[0]);

	measure_time(&program_start, 0);

	/* get port */
	port = atoi(argv[2]);

	/* perform the scan */
	if (syn_scan(argv[1], port) == -1)
		exit(1);

	/* display scan time */
	if (measure_time(&program_end, 0) != -1) {
		printf("\nScan completed after %0.2fs.\n",
			calc_delta(&program_start, &program_end));
	}

	return 0;
}

void usage(char *name) {
	printf("Usage: %s <ip address> <port>\n", name);
	exit(1);
}
