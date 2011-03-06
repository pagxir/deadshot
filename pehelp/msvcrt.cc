#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <signal.h>
#include <math.h>
#include <sys/stat.h>

#include "dllwrap.h"

size_t _argcnt = 0;
char **_arglist = NULL;

#if defined(__POSIX__)
static int cygwin_internal(int a, int b)
{
    printf("cygwin_internal: %d %p\n", a, b);
    return -1;
}

static int *_errno()
{
    printf("call %d\n", errno);
    return &errno;
}

static int * __p__commode(void)
{
    static int __commode = 0;
    return &__commode;
}

static char *** __p___initenv()
{
    static char ** __initenv = NULL;
    return &__initenv;
}

typedef void (**_PVFV)();

static void _initterm(_PVFV *begin, _PVFV *end)
{
    while (begin < end){
        if (*begin != NULL)
            (**begin)();
        begin++;
    }
}


extern char **environ;
static void __getmainargs(int *pargc, char ***pargv, char ***penvp,
        int dowildcard, void *startinfo)
{
    *pargc = _argcnt;
    *pargv = _arglist;
    *penvp = environ;
    printf("call getmainargs\n");
}

static int fmode = 0;
static int *__p__fmode()
{
    return &fmode;
}

static char *** __p__environ(void)
{
    return &environ;
}

static int app_type = 0;
static void __set_app_type(int t)
{
    printf("__set_app_type: %d\n", t);
    app_type = t;
}
#endif

#define MATCH2(fNAME, proxy) \
    if (!strcmp(fNAME, name)){ *pfunc=(void*)proxy; return 0; }

int msvcrt_GetProcAddress(const char *name, void **pfunc)
{
#if defined(__POSIX__)
    MATCH2("??3@YAXPAX@Z", free);
    MATCH2("??2@YAPAXI@Z", malloc);
    MATCH2("_putenv", putenv);
    MATCH2("_access", access);
    MATCH2("_stricmp", strcasecmp);
    MATCH2("_strincmp", strncasecmp);
    MATCH2("_strdup", strdup);
    MATCH2("_stat", stat);

    MATCH2("_stati64", stat);
    MATCH2("remove", remove);
    MATCH2("_utime", utime);
    MATCH2("_exit", exit);
    MATCH2("_cexit", exit);

#define MF(Name) MATCH2(#Name, Name);
    MF(__p___initenv);
    MF(_initterm);
    MF(__p__commode);
#undef XF

#define XF(Name) MATCH2(#Name, Name);
    XF(memcmp);
    XF(bsearch);
    XF(calloc);
    XF(close);
    XF(exit);
    XF(fgets);
    XF(fputs);
    XF(fstat);
    XF(getcwd);
    XF(getenv);
    XF(isatty);
    XF(lseek);
    XF(memchr);
    XF(open);
    XF(putc);
    XF(puts);
    XF(qsort);
    XF(read);
    XF(sprintf);
    XF(strcasecmp);
    XF(strcmp);
    XF(strdup);
    XF(strncasecmp);
    XF(strtoul);
    XF(vfprintf);
    XF(write);
    XF(__getmainargs);
    XF(__p__environ);
    XF(__p__fmode);
    XF(__set_app_type);
    XF(abort);
    XF(atexit);
    XF(fflush);
    XF(fprintf);
    XF(printf);
    XF(fopen);
    XF(free);
    XF(malloc);
    XF(pow);
    XF(tan);
    XF(signal);
    XF(atoi);
    XF(memcpy);
    XF(atof);
    XF(realloc);
    XF(fclose);
    XF(fread);
    XF(memset);
    XF(fwrite);
    XF(memmove);
    XF(strncmp);
    XF(strncpy);
    XF(strerror);
    XF(strlen);
    XF(_errno);
    XF(cygwin_internal);
    XF(strchr);
    XF(strcpy);
    XF(fputc);
    XF(raise);
    XF(strcat);
    XF(strpbrk);
    XF(strstr);
    XF(clock);
    XF(ctime);
    XF(fgetc);
    XF(fgetpos);
    XF(fseek);
    XF(fsetpos);
    XF(perror);
    XF(putchar);
    XF(rewind);
    XF(sscanf);
    XF(strcspn);
    XF(strncat);
    XF(strrchr);
    XF(strspn);
    XF(strtok);
    XF(strtol);
    XF(time);
    XF(ungetc);
    XF(__mb_cur_max);
    XF(rand);
    XF(setvbuf);
    XF(srand);
    XF(strcoll);
    XF(strftime);
    XF(strtod);
    XF(strxfrm);
#undef XF
#endif

    printf("msvcrt.dll call %s missing\n", name);
    return -1;
}
