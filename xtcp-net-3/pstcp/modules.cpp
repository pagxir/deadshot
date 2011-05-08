#include <stdio.h>

#include "modules.h"

void initialize_modules(modules_t * modules_list[])
{
	int i;
	void (*init)(void);

	for (i = 0; modules_list[i]; i++) {
		init = modules_list[i]->init;
		if (init != NULL)
			modules_list[i]->init();
	}
}

void cleanup_modules(modules_t * modules_list[])
{
	int i;
	void (*clean)(void);

	for (i = 0; modules_list[i]; i++) {
		clean = modules_list[i]->clean;
		if (clean != NULL)
			modules_list[i]->clean();
	}
}

