#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

/*
 * Function made for easier program execution time measurement.
 * Returns 0 on succes, -1 on failure. exit_on_err specifies wheter
 * program should exit on failure or not.
 */
int measure_time(struct timespec *tp, bool exit_on_err) {
	if (clock_gettime(CLOCK_MONOTONIC_RAW, tp) == -1) {
		fprintf(stderr, "Unable to measure the time.\n");
		if (exit_on_err)
			exit(1);
		return -1;
	} else 
		return 0;
}

double calc_delta(struct timespec *start, struct timespec *end) {
	return (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec) / 1E9;
}
