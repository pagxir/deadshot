/*
 * chkfreq.c
 *
 * usage: chkfreq [count]
 */

#include <sys/types.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static __inline u_int64_t
rdtsc(void)
{
	u_int32_t eax, edx;
	__asm __volatile("rdtsc" : "=a" (eax), "=d" (edx));
	return (((u_int64_t)edx << 32) | (u_int64_t)eax);
}

int
main(int argc, char *argv[])
{
	int n = 1;
	u_int64_t t1, t2;
	struct timeval tv1, tv2;
	struct timespec ts;

	if (argc > 1)
		n = atoi(argv[1]);

	while (n-- > 0) {
		t1 = rdtsc();
		gettimeofday(&tv1, NULL);

		ts.tv_sec = 0;
		ts.tv_nsec = 990000000;
		nanosleep(&ts, NULL);
	
		do {
			t2 = rdtsc();
			gettimeofday(&tv2, NULL);

			tv2.tv_usec += (tv2.tv_sec - tv1.tv_sec) * 1000000;
			tv2.tv_usec -= tv1.tv_usec;
		} while (tv2.tv_usec < 1000000);

		printf("%llu\n", t2 - t1);
	}

	return 0;
}
