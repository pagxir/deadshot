#include <stdio.h>
#include <string.h>
#include <unistd.h>
#if 0
#include <sys/mman.h>
#include <machine/segments.h>
#include <machine/sysarch.h>

#define       LDT_SEL(idx) ((idx) << 3 | 1 << 2 | 3)

#if 0
#define TEB_SEL_IDX 17
#else
#define TEB_SEL_IDX LDT_AUTO_ALLOC
#endif

#define MODIFY_LDT_CONTENTS_DATA        0
#define MODIFY_LDT_CONTENTS_STACK       1
#define MODIFY_LDT_CONTENTS_CODE        2

static unsigned int fs_ldt = TEB_SEL_IDX;

struct modify_ldt_ldt_s {
    unsigned int  entry_number;
    unsigned long base_addr;
    unsigned int  limit;
    unsigned int  seg_32bit:1;
    unsigned int  contents:2;
    unsigned int  read_exec_only:1;
    unsigned int  limit_in_pages:1;
    unsigned int  seg_not_present:1;
    unsigned int  useable:1;
};

static void ldt_entry2bytes( unsigned long *buffer,
        const struct modify_ldt_ldt_s *content )
{
    *buffer++ = ((content->base_addr & 0x0000ffff) << 16) |
	(content->limit & 0x0ffff);
    *buffer = (content->base_addr & 0xff000000) |
	((content->base_addr & 0x00ff0000)>>16) |
	(content->limit & 0xf0000) |
	(content->contents << 10) |
	((content->read_exec_only == 0) << 9) |
	((content->seg_32bit != 0) << 22) |
	((content->limit_in_pages != 0) << 23) | 0xf000;
}

static void setup_fs_segment(void)
{
    unsigned int ldt_desc = LDT_SEL(fs_ldt);

    __asm__ __volatile__(
            "movl %0,%%eax; movw %%ax, %%fs" : : "r" (ldt_desc)
            :"eax"
            );
}

int setup_ldt()
{
    printf("TEB_SEL_IDX: %d\n", TEB_SEL_IDX);
    unsigned long d[2];
    struct modify_ldt_ldt_s array;
    memset(&array, 0, sizeof(array));
    void *base = mmap(NULL, getpagesize(),
            PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    printf("LDT base: %p\n", base);
    array.base_addr=(int)base;
    array.entry_number=TEB_SEL_IDX;
    array.limit=array.base_addr+getpagesize()-1;
    array.seg_32bit=1;
    array.read_exec_only=0;
    array.seg_not_present=0;
    array.contents=MODIFY_LDT_CONTENTS_DATA;
    array.limit_in_pages=0;
    ldt_entry2bytes( d, &array );
    fs_ldt = (unsigned int)
        i386_set_ldt(TEB_SEL_IDX, (union descriptor *)d, 1);
    printf("setup_ldt: %p\n", fs_ldt);
    setup_fs_segment();
    return 0;
}
#else
int setup_ldt()
{
    return 0;
}
#endif
