#include <stdio.h>

#include "buildin.h"
#include "MSVCRT.h"

extern struct library_t msvcrt_dll;

void register_msvcrt_dll(void)
{
	register_library(&msvcrt_dll);
}

struct library_t msvcrt_dll = {
	0, "MSVCRT.dll", NULL 
};

