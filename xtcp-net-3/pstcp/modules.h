#ifndef _MODULES_H_
#define _MODULES_H_

typedef struct _modules_s {
	void (*init)(void);
	void (*clean)(void);
} modules_t;

void initialize_modules(modules_t * list[]);
void cleanup_modules(modules_t * list[]);
#endif

