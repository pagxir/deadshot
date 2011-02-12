#include <stdio.h>
#include <windows.h>

#include "pertld.h"
#include "peimg_file.h"

int pe_free(void * addr, size_t size)
{
	if (VirtualFree(addr, size, MEM_DECOMMIT | MEM_RELEASE))
		return 0;
	return -1;
}

void * pe_alloc(void * base, size_t size)
{
	DWORD flags = MEM_COMMIT | MEM_RESERVE;
	DWORD prot  = PAGE_EXECUTE_READWRITE;
	return VirtualAlloc(NULL, size, flags, prot);
}

PEFileImage::PEFileImage(const char * path)
{
	m_hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

ssize_t PEFileImage::pread(void * buf, size_t size, size_t off)
{
	DWORD count;
	OVERLAPPED overlapped = {0};
	overlapped.Offset = off;

	if (ReadFile(m_hFile, buf, size, &count, &overlapped))
		return count;

	return -1;
}

PEFileImage::~PEFileImage()
{
	if (!IsValid()) 
		return;

	CloseHandle(m_hFile);
	m_hFile = INVALID_HANDLE_VALUE;
}

typedef int __stdcall ImageView_Fullscreen(const char * path);

int main(int argc, char * argv[])
{
	Obj_Entry * obj;
	ImageView_Fullscreen * pImageView_Fullscreen;

	PEFileImage img("shimgvw.dll");

	if (!img.IsValid()) 
		return -1;
		
	obj = peLoadImage(&img);
	if (obj == NULL)
		return -1;

#if 1
	pImageView_Fullscreen = (ImageView_Fullscreen *)
			peGetProcAddress(obj, "ImageView_Fullscreen");

	printf("pImageView_Fullscreen: %p\n", pImageView_Fullscreen);
	if (pImageView_Fullscreen != NULL) {
		int code = pImageView_Fullscreen("1007292235afe592915c5257eb.jpg");
		printf("code: %d\n", code);
	}

#endif

	peCallMainEntry(obj);

	return 0;
}
