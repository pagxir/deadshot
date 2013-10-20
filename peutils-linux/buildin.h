#ifndef _BUILDIN_H_
#define _BUILDIN_H_

struct library_t {
	int refcnt;
	char *name;
	struct library_t *next;
};

int register_library(struct library_t *libdat);
int unregister_library(struct library_t *libdat);

void * LoadLibrary(const char *path);
void * GetProcAddress(void *hModule, const char *name);
#endif

