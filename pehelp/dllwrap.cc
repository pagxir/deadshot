#include <string.h>
#include <math.h>
#include <stdio.h>

#include <string>
#include <map>

#include "pehlp.h"
#include "dllwrap.h"

static int purecall(char *name)
{
    void * p = *(void **)(name + strlen(name) + 1);
    printf("missing call: %s@%p\n", name, p);
    exit(0);
#if 1
    *(name - 14) = 0x31;
    *(name - 13) = 0xc0;
    *(name - 12) = 0xc3;
#endif
    return 0;
}

extern void *__this_handle;
extern void *peaux_LoadLibrary(const char*);
static void *GetModuleHandleW(const short *wname)
{
    int i=0;
    char name[1024];
    if (wname == NULL)
        return __this_handle;

    do name[i] = wname[i];
    while(wname[i++]);

    if (!strcasecmp(name, "KERNEL32.DLL"))
        return __g_kernel32;

    printf("GetModuleW: %s\n", name);
    return peaux_LoadLibrary(name);
}

static void *GetModuleHandleA(const char *name)
{
    if (name == NULL)
        return __this_handle;
    printf("GetModuleA: %s\n", name);
    return peaux_LoadLibrary(name);
}

static std::map<std::string, void*> __badcall_list;

char *exec_alloc(void *imgbase, size_t count);

void *advapi32_GetProcAddress(const char *libname,
        const char *fName, const void *addr)
{
    void *pfunc = NULL;

    MATCH("GetProcAddress", peaux_GetProcAddress);
    MATCH("GetModuleHandleA", GetModuleHandleA);
    MATCH("GetModuleHandleW", GetModuleHandleW);
    MATCH("LoadLibraryA", peaux_LoadLibrary);
    MATCH("DbgPrint", printf);

	if (!strcasecmp(libname, "ntoskrnl.exe")
			&& !ntoskrnl_GetProcAddress(fName, &pfunc))
		return pfunc;

    if (!strcasecmp(libname, "kernel32.dll")
            && !kernel32_GetProcAddress(fName, &pfunc))
        return pfunc;

    if (!strcasecmp(libname, "msvcrt.dll")
            && !msvcrt_GetProcAddress(fName, &pfunc))
        return pfunc;
  
    if (!strcasecmp(libname, "ws2_32.dll")
            && !wsock32_GetProcAddress(fName, &pfunc))
        return pfunc;

    char functbl[] = {
         0xb8, 0x70, 0x84, 0x04, 0x08, 0x68, 0xd7, 0x11,
         0x30, 0x30, 0xff, 0xd0, 0x58, 0xc3, 0x00,
    };

    if (__badcall_list.find(fName) != __badcall_list.end())
        return __badcall_list[fName];

    char * pbadcall = exec_alloc(NULL, 0x16 + strlen(fName) + strlen(libname));
    int fend = sprintf(pbadcall, "%s%s.%s", functbl, libname, fName);
    *(size_t *)(pbadcall + 1) = (size_t)(purecall);
    *(size_t *)(pbadcall + 6) = (size_t)(pbadcall + 14);
    *(size_t *)(pbadcall + fend + 1) = (size_t)addr;
    __badcall_list[fName] = pbadcall;
    printf("%s is missing\n", fName);
    return (void*)pbadcall;
}
