#include <stdio.h>
#include <windows.h>

#include "pertld.h"
#include "peimg_file.h"

#define FIX(name) name##fixup

HICON WINAPI FIX(LoadIconA)(HINSTANCE hInstance, LPCSTR lpIconName)
{
	return (HICON)LoadIconA(hInstance, lpIconName);
}

HICON WINAPI FIX(LoadIconW)(HINSTANCE hInstance, LPCWSTR lpIconName)
{
	return (HICON)LoadIconW(hInstance, lpIconName);
}

HCURSOR WINAPI FIX(LoadCursorW)(HINSTANCE hInstance, LPCWSTR lpCursorName)
{
	return (HCURSOR)LoadCursorW(hInstance, lpCursorName);
}

HCURSOR WINAPI FIX(LoadCursorA)(HINSTANCE hInstance, LPCSTR lpCursorName)
{
	return (HCURSOR)LoadCursorA(hInstance, lpCursorName);
}

int WINAPI FIX(LoadStringA)(HINSTANCE hInstance, UINT uID, 
		LPSTR lpBuffer, int nBufferMax)
{
	return LoadStringA(hInstance, uID, lpBuffer, nBufferMax);
}

int WINAPI FIX(LoadStringW)(HINSTANCE hInstance, UINT uID, 
		LPWSTR lpBuffer, int nBufferMax)
{
	return LoadStringW(hInstance, uID, lpBuffer, nBufferMax);
}

HACCEL WINAPI FIX(LoadAcceleratorsA)(HINSTANCE hInstance, LPCTSTR lpTableName)
{
	return (HACCEL)LoadAcceleratorsA(hInstance, lpTableName);
}

void * resfunc_fixup(const char  * name)
{
#define XX(f) \
	if (strcmp(name, #f) == 0) { \
		printf("name: %s\n", name); \
		return (void *)f##fixup; \
	}

	XX(LoadIconW);
	XX(LoadIconA);
	XX(LoadAcceleratorsA);
	XX(LoadCursorA);
	XX(LoadCursorW);
	XX(LoadStringW);
	XX(LoadStringA);
#undef XX
	return NULL;
};

int pe_free(void * addr, size_t size)
{
	if (VirtualFree(addr, size, MEM_DECOMMIT | MEM_RELEASE))
		return 0;
	return -1;
}

void * pe_alloc(void * base, size_t size)
{
	void * virt = 0;
	DWORD flags = MEM_COMMIT | MEM_RESERVE;
	DWORD prot  = PAGE_EXECUTE_READWRITE;
	virt = VirtualAlloc(base, size, flags, prot);
	return (virt == NULL)? VirtualAlloc(0, size, flags, prot): virt;
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

typedef int ImageView_Fullscreen(const char * path);

int main(int argc, char * argv[])
{
	Obj_Entry * obj;
	ImageView_Fullscreen * pImageView_Fullscreen;

	PEFileImage img("C:\\WINDOWS\\system32\\shimgvw.dll");

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
		int code = pImageView_Fullscreen(""); //H:\\OpenSource\\peutils\\IMG_5041.jpg");
		printf("code: %d\n", code);
	}

#endif

	peCallMainEntry(obj);

	return 0;
}
