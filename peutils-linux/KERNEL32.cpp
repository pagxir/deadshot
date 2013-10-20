#include <stdio.h>

#include "buildin.h"
#include "KERNEL32.h"

extern struct library_t kernel32_dll;

void register_kernel32_dll(void)
{
	register_library(&kernel32_dll);
}

struct library_t kernel32_dll = {
	0, "KERNEL32.dll", NULL 
};

