#ifndef __PERTLD_H__
#define __PERTLD_H__

class PEImage;
typedef struct _pe_object Obj_Entry;

Obj_Entry * peLoadImage(PEImage * image);
void * peGetProcAddress(Obj_Entry * obj, const char * name);

void peCallMainEntry(Obj_Entry * obj);
unsigned int peCallDllEntry(Obj_Entry * obj, unsigned int fdwReason);

int pe_free(void * addr, size_t size);
void * pe_alloc(void * base, size_t size);


class PEImage {
	public:
		virtual ssize_t pread(void * buf, size_t size, size_t off) = 0;
};

#endif

