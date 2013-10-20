#include <stdio.h>
#include <string.h>

#include "buildin.h"

static struct library_t *_dll_first = 0;

int register_library(struct library_t *dllp)
{
	dllp->next = _dll_first;
	_dll_first = dllp;
	return 0;
}

void * LoadLibrary(const char *path)
{
	struct library_t *dllp;

	dllp = _dll_first;
	while (dllp != NULL) {
		if (strcmp(path, dllp->name) == 0)
			break;
		dllp = dllp->next;
	}

	if (dllp != NULL) {
		dllp->refcnt++;
		return dllp;
	}

	fprintf(stderr, "fixme: %s missing\n", path);
	return NULL;
}

static int wrap_stub(void)
{
	fprintf(stderr, "fixme: call wrap_stub\n");
	return 0;
}

void * GetProcAddress(void *hModule, const char *name)
{
	printf("GetProcAddress %s\n", name);
	return (void *)wrap_stub;
}

