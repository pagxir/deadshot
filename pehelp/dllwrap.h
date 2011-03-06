extern void *__g_kernel32;

void *advapi32_GetProcAddress(const char *libname, const char *fName,
        const void *addr);

int ntoskrnl_GetProcAddress(const char *fName, void **addr);
int kernel32_GetProcAddress(const char *fName, void **addr);
int wsock32_GetProcAddress(const char *fName, void **addr);
int msvcrt_GetProcAddress(const char *fName, void **addr);

#define MATCH(name, proxy) if ( !strcmp(fName, name) )return (void*)proxy;
