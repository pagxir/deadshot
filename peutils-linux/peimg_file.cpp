#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/version.h>

#include <asm/unistd.h>
#include <asm/ldt.h>

#include "MSVCRT.h"
#include "KERNEL32.h"
#include "pertld.h"
#include "peimg_file.h"

#define FIX(name) name##fixup
#define       TEB_SEL_IDX 17
#define       LDT_SEL(idx) ((idx) << 3 | 1 << 2 | 3)
extern "C" int modify_ldt(int func, void *ptr, unsigned long bytecount);

void * resfunc_fixup(const char  * name)
{
#define XX(f) \
	if (strcmp(name, #f) == 0) { \
		printf("name: %s\n", name); \
		return (void *)f##fixup; \
	}

#undef XX
	return NULL;
};

int pe_free(void * addr, size_t size)
{
	return munmap(addr, size);
}

void * pe_alloc(void * base, size_t size)
{
	int prot;
	int flag;
	void *retval;

	flag = MAP_PRIVATE| MAP_ANONYMOUS;
	prot = PROT_EXEC| PROT_WRITE| PROT_READ;
	retval = mmap(base, size, prot, flag,  -1, 0);
	if (retval == MAP_FAILED)
		retval = mmap(NULL, size, prot, flag,  -1, 0);
	return retval;
}

PEFileImage::PEFileImage(const char * path)
{
	m_hFile = open(path, O_RDONLY);
}

ssize_t PEFileImage::pread(void * buf, size_t size, size_t off)
{
	return ::pread(m_hFile, buf, size, off);
}

PEFileImage::~PEFileImage()
{
	if (!IsValid()) 
		return;

	close(m_hFile);
	m_hFile = -1;
}


extern void *fs_seg;

typedef struct {
  void* fs_seg;
  char* prev_struct;
} ldt_fs_t;


#define LDT_ENTRIES     8192
#define LDT_ENTRY_SIZE  8
#pragma pack(4)
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

#define MODIFY_LDT_CONTENTS_DATA        0
#define MODIFY_LDT_CONTENTS_STACK       1
#define MODIFY_LDT_CONTENTS_CODE        2
#ifndef       TEB_SEL_IDX
#define       TEB_SEL_IDX     17
#endif

static unsigned int fs_ldt = TEB_SEL_IDX;

void *fs_seg = 0;
void Setup_FS_Segment(void)
{
    unsigned int ldt_desc = LDT_SEL(fs_ldt);

    __asm__ volatile(
	"movl %0,%%eax; movw %%ax, %%fs" : : "r" (ldt_desc)
	:"eax"
    );
}

void setup_ldt()
{
	ldt_fs_t* ldt_fs = (ldt_fs_t *)malloc(sizeof(ldt_fs_t));
	struct modify_ldt_ldt_s array;
	fs_seg=
		ldt_fs->fs_seg = mmap(NULL, getpagesize(),
				PROT_READ | PROT_WRITE, MAP_PRIVATE| MAP_ANONYMOUS, -1, 0);
	memset(&array, 0, sizeof(array));
	array.base_addr=(int)ldt_fs->fs_seg;
	array.entry_number=TEB_SEL_IDX;
	array.limit=array.base_addr+getpagesize()-1;
	array.seg_32bit=1;
	array.read_exec_only=0;
	array.seg_not_present=0;
	array.contents=MODIFY_LDT_CONTENTS_DATA;
	array.limit_in_pages=0;
	modify_ldt(0x1, &array, sizeof(struct modify_ldt_ldt_s));

	Setup_FS_Segment();

}

int main(int argc, char * argv[])
{
	int i;
	Obj_Entry * obj;
	setup_ldt();

	register_msvcrt_dll();
	register_kernel32_dll();

	for (i = 1; i < argc; i++) {
		PEFileImage img(argv[i]);

		if (!img.IsValid()) 
			continue;
		
		obj = peLoadImage(&img);
		if (obj == NULL)
			continue;

		peGetProcAddress(obj, "DLL_delay");
		peGetProcAddress(obj, "DLL_version");
		peCallMainEntry(obj);
	}

	//peCallMainEntry(obj);

	return 0;
}

