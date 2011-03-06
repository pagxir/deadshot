#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <windows.h>
#include <stdio.h>

#include "pehlp.h"
#define __stdcall __attribute__((__stdcall__))

extern char g__drv43260[];
extern char g__libfaad2[];
extern char g__cook3260[];

#if 0
extern "C"{
static size_t (__stdcall *pfRADecode)(size_t, size_t, size_t,
       	size_t, size_t, size_t);
size_t __stdcall RADecode(size_t a, size_t b, size_t c,
       	size_t d, size_t e, size_t f)
{
    return pfRADecode(a, b, c, d, e, f);
}

static size_t (__stdcall *pfRAInitDecoder)(size_t, size_t);
size_t __stdcall RAInitDecoder(size_t a, size_t b)
{
    return pfRAInitDecoder(a, b);
}

static size_t (__stdcall *pfRAOpenCodec2)(size_t, size_t);
size_t __stdcall RAOpenCodec2(size_t a, size_t b)
{
    return pfRAOpenCodec2(a, b);
}

static size_t (__stdcall *pfRV40toYUV420Init)(size_t, size_t);
size_t __stdcall RV40toYUV420Init(size_t a, size_t b)
{
    return pfRV40toYUV420Init(a, b);
}

static size_t (__stdcall *pfRV40toYUV420Transform)(size_t, size_t,
       	size_t, size_t, size_t);
size_t __stdcall RV40toYUV420Transform(size_t a, size_t b,
       	size_t c, size_t d, size_t e)
{
    return pfRV40toYUV420Transform(a, b, c, d, e);
}

static size_t (*pfNeAACDecClose)(size_t);
size_t NeAACDecClose(size_t a)
{
    return pfNeAACDecClose(a);
}

static size_t (*pfNeAACDecDecode)(size_t, size_t, size_t, size_t);
size_t NeAACDecDecode(size_t a, size_t b, size_t c, size_t d)
{
    return pfNeAACDecDecode(a, b, c, d);
}

static size_t (*pfNeAACDecGetCurrentConfiguration)(size_t);
size_t NeAACDecGetCurrentConfiguration(size_t a)
{
    return pfNeAACDecGetCurrentConfiguration(a);
}

static size_t (*pfNeAACDecInit)(size_t, size_t, size_t, size_t, size_t);
size_t NeAACDecInit(size_t a, size_t b, size_t c, size_t d, size_t e)
{
    return pfNeAACDecInit(a, b, c, d, e);
}

static size_t (*pfNeAACDecInit2)(size_t, size_t, size_t, size_t, size_t);
size_t NeAACDecInit2(size_t a, size_t b, size_t c, size_t d, size_t e)
{
    return pfNeAACDecInit2(a, b, c, d, e);
}

static size_t (*pfNeAACDecOpen)();
size_t NeAACDecOpen()
{
    return pfNeAACDecOpen();
}

static size_t (*pfNeAACDecSetConfiguration)(size_t, size_t);
size_t NeAACDecSetConfiguration(size_t a, size_t b)
{
    return pfNeAACDecSetConfiguration(a, b);
}
};

size_t apifix_setup()
{
    void *hp = NULL;
    void **pf = NULL;

    printf("Load Library!\n");
#define XF(Name) pf=(void**)&pf##Name; \
    *pf = peaux_GetProcAddress(hp, #Name); \
    assert(*pf != NULL);

    hp = peMapImage(g__drv43260);
    XF(RV40toYUV420Init);
    XF(RV40toYUV420Transform);

    hp = peMapImage(g__cook3260);
    XF(RAInitDecoder);
    XF(RAOpenCodec2);
    XF(RADecode);

    hp = peMapImage(g__libfaad2);
    XF(NeAACDecInit);
    XF(NeAACDecInit2);
    XF(NeAACDecOpen);
    XF(NeAACDecClose);
    XF(NeAACDecDecode);
    XF(NeAACDecSetConfiguration);
    XF(NeAACDecGetCurrentConfiguration);
#undef XF

    return 0;
}

#endif

char *exec_alloc(void *imgbase, size_t count)
{
    void *pvoid = VirtualAlloc(imgbase, count,
	    MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pvoid == NULL){
       	pvoid = VirtualAlloc(NULL, count,
	       	MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	   	printf("^%p %p\n", pvoid, imgbase);
    }
	printf("^%p %p\n", pvoid, imgbase);
    return (char*)pvoid;
}
