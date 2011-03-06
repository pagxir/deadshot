#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(__POSIX__)
#include <pthread.h>
#endif
#include <string>
#include <vector>

#include "dllwrap.h"

#ifndef WINAPI
#define WINAPI __attribute__((__stdcall__))
#endif

typedef struct _FILETIME {
    size_t dwLowDateTime;
    size_t dwHighDateTime;
} FILETIME, *LPFILETIME;

static void WINAPI GetSystemTimeAsFileTime(LPFILETIME *lptime)
{
    memset(lptime, 0, sizeof(FILETIME));
}

static size_t WINAPI GetCurrentProcessId()
{
#if defined(__POSIX__)
    return (size_t)getpid();
#else
	return 0;
#endif
}

static size_t WINAPI GetCurrentThreadId()
{
#if defined(__POSIX__)
    return (size_t)pthread_self();
#else
	return 0;
#endif
}

static size_t GetTickCount()
{
    return time(NULL);
}

static ssize_t WINAPI QueryPerformanceCounter(int64_t *pcounter)
{
    return 1;
}

static void * WINAPI HeapCreate(size_t a, size_t b, size_t c)
{
    static size_t h;
    return &h;
}

static uint16_t __atom_base = 0x1982;
static std::vector<std::string> __atom_list;

static size_t GetAtomNameA(uint16_t atom, char *buff, size_t bufsz)
{
    int ix;
    std::string name;
    if (atom < __atom_base)
        return 0;

    ix = atom - __atom_base;
    if (ix < __atom_list.size()) {
        name = __atom_list[ix];
        if (name.size() > bufsz)
            return 0;
        strcpy(buff, name.c_str());
        return name.size();
    }
    return 0;
}

static uint16_t AddAtomA(const char *name)
{
    uint16_t ix = __atom_list.size();
    std::string key = name;
    __atom_list.push_back(key);
    return __atom_base+ix;
}

static uint16_t FindAtomA(const char *name)
{
    int ix;
    for (ix = 0; ix < __atom_list.size(); ix++)
        if (__atom_list[ix] == name)
            return __atom_base+ix;
    return 0;
}

static void *__unhandled_exception_filter = NULL;
static void *SetUnhandledExceptionFilter(void *ptr)
{
    void *oldptr = __unhandled_exception_filter;
    printf("call SetUnhandledExceptionFilter: %p\n", ptr);
    __unhandled_exception_filter = ptr;
    return oldptr;
}

static char *GetCommandLineA()
{
    static char path[1024] = "setup.exe"; 
    printf("call exp_GetCommandLineA\n");
    return path;
}

static size_t GetFullPathNameA(const char *name, size_t size,
        char *buffer, char **filepa)
{
    int len = 0;
    printf("%s %d %p %p\n", name, size, buffer, filepa);
    if (name && name[0]!='/') {
        getcwd(buffer, size);
        len = strlen(buffer);
        filepa? *filepa = &buffer[len+1]: 0;
        return len + sprintf(buffer, "/%s", name);
    }
    return 0;
}

static size_t CharLowerBuffA(char *buff, size_t count)
{
    int i;
    for (i = 0; i < count; i++)
        buff[i] = tolower(buff[i]);
    return i;
}

#define MATCH2(fNAME, proxy) \
    if ( !strcmp(fNAME, name) ){ *pfunc = (void*)proxy; return 0; }

int kernel32_GetProcAddress(const char *name, void **pfunc)
{
    MATCH2("ExitProcess", exit);
    MATCH2("Sleep", usleep);

#define XF(Name) MATCH2(#Name, Name)
    XF(AddAtomA);
    XF(FindAtomA);
    XF(GetAtomNameA);
    XF(GetCommandLineA);
    XF(SetUnhandledExceptionFilter);
#undef XF
    printf("fixme: %s@kernel32.dll\n", name);
    return -1;
}

static int kernel32_base = 0;
void * __g_kernel32 = &kernel32_base;
