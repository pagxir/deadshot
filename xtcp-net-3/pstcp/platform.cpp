#include <time.h>
#include <fcntl.h>

#include "platform.h"

void setnonblock(int file)
{
	u_long mode = 1;
#ifdef _WIN32_
	ioctlsocket(file, FIONBIO, &mode);
#else
	mode = fcntl(file, F_GETFL);
	fcntl(file, F_SETFL, O_NONBLOCK| mode);
#endif
	return;
}

unsigned int GetTickCount(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

