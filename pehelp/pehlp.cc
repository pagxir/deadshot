#include <stdio.h>
#include <assert.h>
#include <string>
#include <map>

#ifdef __POSIX__
#include <sys/mman.h>
#endif

#include "pehlp.h"
#include "pehdr32.h"
#include "dllwrap.h"

#if __POSIX__
#define GetModuleHandle peaux_LoadLibrary
#define GetProcAddress peaux_GetProcAddress
#define LoadLibrary peaux_LoadLibrary
#else
#endif

typedef WORD *LPWORD;
typedef DWORD *LPDWORD;

static int bindThunkArrayPointer(char *name, char image[], int thunk, int IAT)
{
    void *hModule = NULL, *tM = NULL;
    PIMAGE_THUNK_DATA pThunkSave = (PIMAGE_THUNK_DATA)&image[IAT];
    PIMAGE_THUNK_DATA pThunk = thunk? (PIMAGE_THUNK_DATA)&image[thunk]: pThunkSave;

    assert((char*)pThunk != image);

#if 1
    printf("LoadLibrary: %s\n", name);
#endif

#if 0
    if ((tM = GetModuleHandle(name)) || (tM = LoadLibrary(name)))
        hModule = tM;
#endif

    char fnbuff[1024];
    if (hModule == NULL) {
        for (PIMAGE_THUNK_DATA p = pThunk; p->u1.Ordinal; p++, pThunkSave++) {
            void * addr = &(pThunkSave->u1.Ordinal);
            if (IMAGE_ORDINAL_FLAG & p->u1.Ordinal) {
                sprintf(fnbuff, "%d", name, p->u1.Ordinal & 0xFFFF);
                pThunkSave->u1.Ordinal = (int)advapi32_GetProcAddress(name, fnbuff, addr);
            }else{
                PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)&image[p->u1.Ordinal];
                pThunkSave->u1.Ordinal = (int)advapi32_GetProcAddress(name, (const char*)(pName->Name), addr);
            }
		   	assert (pThunkSave->u1.Ordinal != 0);
        }
    } else {
        for (PIMAGE_THUNK_DATA p = pThunk; p->u1.Ordinal; p++, pThunkSave++) {
            if (IMAGE_ORDINAL_FLAG & p->u1.Ordinal) {
                size_t iName = (0x7FFFFFFF & p->u1.Ordinal);
                sprintf(fnbuff, "!%dnoName", iName);
                pThunkSave->u1.Ordinal = (size_t)GetProcAddress(hModule, (char*)iName);
            } else {
                PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)&image[p->u1.Ordinal];
                sprintf(fnbuff, "%s", pName->Name);
                pThunkSave->u1.Ordinal = (size_t)GetProcAddress(hModule, (char*)(pName->Name));
            }
            if (pThunkSave->u1.Ordinal == 0) {
                pThunkSave->u1.Ordinal = (int)advapi32_GetProcAddress(name,
					   	fnbuff, &(pThunkSave->u1.Ordinal));
            }
		   	assert(pThunkSave->u1.Ordinal != 0);
        }
    }
    return 0;
}
 
static int walkRelocTable(char image[], size_t off, size_t size, char *base)
{
     int delta = image - base;
     printf("image: %p %p\n", image, base);
     size_t ibrent = 0, lastVA = 1;

     for (char * p = &image[off];
			 lastVA != 0 && p < &image[off + size]; p += ibrent) { 
         PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)p;
         lastVA = pReloc->VirtualAddress;
         ibrent = pReloc->SizeOfBlock;

         for (LPWORD fixup = (LPWORD)(pReloc + 1); fixup < (LPWORD)(p + ibrent); fixup++) {
             if (IMAGE_REL_BASED_HIGHLOW == (*fixup >> 12)) {
                 LPDWORD lpword = (LPDWORD)&image[lastVA + (*fixup & 0xFFF)];
                 *lpword += delta;
             }
		 }
     }

     return 0;
}
 
static int walkImportTable(char image[], size_t off, size_t size)
{
    typedef PIMAGE_IMPORT_DESCRIPTOR PID;
    
    for (PID p = (PID)&image[off]; p < (PID)&image[off + size] && p->Name; p++)
        if (-1 == bindThunkArrayPointer(&p->Name[image], image,
                    (size_t)p->DUMMYUNIONNAME.OriginalFirstThunk, (size_t)p->FirstThunk))
            return -1;
    return 0;
}

static int peWalkDynLink(void *hModule);
extern char *exec_alloc(void *base, size_t count);
 
void *peMapImage(char* image)
{
     size_t ix;
     size_t hdrsz;
     IMAGE_NT_HEADERS ntHdr;
     IMAGE_DOS_HEADER dosHdr;

     memcpy(&dosHdr, image, sizeof(dosHdr));

     if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE)
         return 0;

     char *p = &image[dosHdr.e_lfanew];
     memcpy(&ntHdr, p, sizeof(ntHdr));
     p += sizeof(ntHdr);

     if (ntHdr.Signature != IMAGE_NT_SIGNATURE)
         return 0;

     void *imgbase  = (void*)ntHdr.OptionalHeader.ImageBase;
     size_t imagesz = ntHdr.OptionalHeader.SizeOfImage;
     size_t nSection = ntHdr.FileHeader.NumberOfSections;

#ifndef __POSIX__
     char *reloc_base = exec_alloc(imgbase, imagesz);
#else
     //char *reloc_base = new char[imagesz];
     char *image_base = (char*)ntHdr.OptionalHeader.ImageBase;

     char *reloc_base = (char*) mmap(image_base, imagesz, 
             PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANON, -1, 0);
#endif

     memset(reloc_base, 0, imagesz);
     IMAGE_SECTION_HEADER *pSection = new IMAGE_SECTION_HEADER[nSection];

     memcpy(pSection, p, sizeof(IMAGE_SECTION_HEADER) * nSection);
     hdrsz = ntHdr.OptionalHeader.SizeOfHeaders;

     p = image;
     memcpy(reloc_base, p, hdrsz);
     p += hdrsz;

     for (ix = 0; ix < nSection; ix++) {
         if (pSection[ix].SizeOfRawData > 0) {
             p = &image[pSection[ix].PointerToRawData];
             memcpy(reloc_base + pSection[ix].VirtualAddress,
					 p, pSection[ix].SizeOfRawData);
         }
     }
     peWalkDynLink(reloc_base);
     delete[] (pSection);
     pSection = NULL;
     return reloc_base;

fail_exit:
     delete[] (pSection);
     delete[] reloc_base;
     return NULL;
}
 
static void *peLoadImage(FILE *fp)
{
     size_t ix;
     size_t hdrsz;
     IMAGE_NT_HEADERS ntHdr;
     IMAGE_DOS_HEADER dosHdr;

     if (fread(&dosHdr, sizeof(dosHdr), 1, fp) != 1)
         return 0;

     if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE)
         return 0;

     if (fseek(fp, dosHdr.e_lfanew, SEEK_SET) != 0)
         return 0;
     
     if (fread(&ntHdr, sizeof(ntHdr), 1, fp) != 1)
         return 0;

     if (ntHdr.Signature != IMAGE_NT_SIGNATURE)
         return 0;

	 void *imgbase  = (void*)ntHdr.OptionalHeader.ImageBase;
     size_t imagesz = ntHdr.OptionalHeader.SizeOfImage;
     size_t nSection = ntHdr.FileHeader.NumberOfSections;

#ifndef __POSIX__
     char *reloc_base = exec_alloc(imgbase, imagesz);
#else
     char *image_base = (char*)ntHdr.OptionalHeader.ImageBase;

     char *reloc_base = (char*) mmap(image_base, imagesz, 
             PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANON, -1, 0);
#endif

	 memset(reloc_base, 0, imagesz);
     IMAGE_SECTION_HEADER *pSection = new IMAGE_SECTION_HEADER[nSection];

     if (fread(pSection, sizeof(IMAGE_SECTION_HEADER), nSection, fp) != nSection)
         goto fail_exit;

     hdrsz = ntHdr.OptionalHeader.SizeOfHeaders;

     if (fseek(fp, 0, SEEK_SET) != 0)
         goto fail_exit;
     
     if (fread(reloc_base, 1, hdrsz, fp) != hdrsz)
         goto fail_exit;

     for (ix=0; ix<nSection; ix++) {
         if (pSection[ix].SizeOfRawData > 0)
             if (fseek(fp, pSection[ix].PointerToRawData, SEEK_SET) != 0
                     || fread(reloc_base+pSection[ix].VirtualAddress, pSection[ix].SizeOfRawData, 1, fp) != 1)
                 goto fail_exit;
#if defined(__POSIX__)
         mprotect(reloc_base, imagesz, PROT_READ|PROT_WRITE|PROT_EXEC);
#endif
     }
     delete[] (pSection);
     pSection = NULL;
     return reloc_base;

fail_exit:
     delete[] (pSection);
     delete[] reloc_base;
     return NULL;
}

static int peWalkDynLink(void *hModule)
{ 
    char *image = (char *)hModule;
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHdr  = (PIMAGE_NT_HEADERS)(image + pDosHdr->e_lfanew);

    IMAGE_DATA_DIRECTORY dirent = pNtHdr->OptionalHeader.DataDirectory[1];
    if (-1 == walkImportTable(image, dirent.VirtualAddress, dirent.Size))
        return -1;

    dirent = pNtHdr->OptionalHeader.DataDirectory[5];
    if (-1 == walkRelocTable(image, dirent.VirtualAddress, dirent.Size,
			   	(char*)pNtHdr->OptionalHeader.ImageBase))
        return -1;

    if (pNtHdr->OptionalHeader.AddressOfEntryPoint) {
        typedef void (* TDllInit)(void * a, int b, int c);
        TDllInit dllInit = 
            (TDllInit)&pNtHdr->OptionalHeader.AddressOfEntryPoint[image];
#if 0
        asm("movl %0, %%edi;"::"r"(dllInit));

        dllInit(image, 1, 0);
        /*dllInit(image, 2, 0);*/
#endif
    }

    return 0;
}

static std::map<std::string, void *> __loaded_library;

static void *__peaux_LoadLibrary(const char *path)
{

    FILE *pefile = NULL;
    void *peImage = NULL;
    const char *split, *key;
   
    split = strchr(path, '\\');
    key = split? (split + 1): path;
    split = strchr(key, '/');
    key = split? (split + 1): key;

    if (__loaded_library.find(key) 
            != __loaded_library.end())
        return __loaded_library[key];

    if (pefile = fopen(path, "rb")) {
        if (peImage = peLoadImage(pefile)) {
			printf("peLoadImage: %s\n", path);
            __loaded_library[key] = peImage;
            if (-1 == peWalkDynLink(peImage)) {
                __loaded_library.erase(key);
                free(peImage);
                peImage = 0;
            }
		   	printf("peWalkDynLink: %s\n", path);
        }
        fclose(pefile);
    }

    return peImage;
}

void *peaux_GetEntryPoint(void *hModule)
{
    const char *image = (const char *)hModule;
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHdr  = (PIMAGE_NT_HEADERS)(image + pDosHdr->e_lfanew);
    return (void *)(image + pNtHdr->OptionalHeader.AddressOfEntryPoint);
}

static void *__peaux_GetProcAddress(void* hModule, const char *fName)
{
    size_t i, exptab, expsz;
    unsigned short *EOT;
    unsigned long *AOF, *pNames;
    const char *image = (const char *)hModule;
    PIMAGE_DOS_HEADER pDosHdr=(PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHdr=(PIMAGE_NT_HEADERS)&image[pDosHdr->e_lfanew];

    expsz  = pNtHdr->OptionalHeader.DataDirectory[0].Size;
    exptab = pNtHdr->OptionalHeader.DataDirectory[0].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)&image[exptab];

    if (expsz >= sizeof(IMAGE_EXPORT_DIRECTORY)) {
        AOF = (unsigned long*)&image[(int)pExport->AddressOfFunctions];
        EOT = (unsigned short*)&image[(int)pExport->AddressOfNameOrdinals];
        pNames = (unsigned long*)&image[(int)pExport->AddressOfNames];
        for(i = 0; i < pExport->NumberOfNames; i++) {
            if (0 == strcmp(image+pNames[i], fName))
                return (void*)&i[EOT][AOF][image];
        }
    }
    return 0;
}

void *peaux_LoadLibrary(const char *path)
{
    if (path != NULL && path[0] != 0)
        return __peaux_LoadLibrary(path);
    return NULL;
}

void *peaux_GetProcAddress(void* hModule, const char *fName)
{
    if (hModule != NULL)
        if (fName != NULL && fName[0] != 0)
            return __peaux_GetProcAddress(hModule, fName);
    return NULL;
}

void peaux_FreeLibrary(void *hModule)
{
    free(hModule);
}
