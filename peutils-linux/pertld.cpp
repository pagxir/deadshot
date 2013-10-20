#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "pe32.h"
#include "pertld.h"
#include "buildin.h"

#define IMAGE_FILE_DLL 0x2000

#define PAGESIZE (4096)
#define DLL_PROCESS_ATTACH 1

#define VERB(exp)  exp

typedef WORD * LPWORD;
typedef DWORD * LPDWORD;

struct _pe_object {
	int delta;
	void * dllentry;
	void * exeentry;

	size_t relocsize;
	char * relocbase;

	size_t impsize;
	PIMAGE_IMPORT_DESCRIPTOR imptable;

	size_t expsize;
	PIMAGE_EXPORT_DIRECTORY exptable;

	size_t ressize;
	PIMAGE_RESOURCE_DIRECTORY restable;

	size_t relsize;
	char * reltable;
};

void * resfunc_fixup(const char  * name);

size_t GetProcAddress_fixup(void * hModule, const char * name)
{
	void * p = resfunc_fixup(name);
	if (p != NULL)
		return (size_t)p;

	return (size_t)GetProcAddress(hModule, name);
}

static int BindThunkArray(Obj_Entry * obj, char * name,
		 PIMAGE_THUNK_DATA pthunkBind, const PIMAGE_THUNK_DATA pthunkKeep)
{
	size_t index;
	char fnname[1024];
	void * hModule = NULL;

	PIMAGE_THUNK_DATA pthunk;
	PIMAGE_IMPORT_BY_NAME pimp_by_name;

	VERB(printf("LoadLibrary: %s\n", name));

	hModule = LoadLibrary(name);
	assert(hModule != NULL);

	for (pthunk = pthunkKeep; pthunk->u1.Ordinal; pthunk++, pthunkBind++) {
		if (IMAGE_ORDINAL_FLAG & pthunk->u1.Ordinal) {
			index = (0x7FFFFFFF & pthunk->u1.Ordinal);
			sprintf(fnname, "!%ldnoName", index);
			pthunkBind->u1.Ordinal = (size_t)GetProcAddress(hModule, (char *)index);
		} else {
			pimp_by_name = (PIMAGE_IMPORT_BY_NAME)(obj->relocbase + pthunk->u1.Ordinal);
			sprintf(fnname, "%s", pimp_by_name->Name);
			pthunkBind->u1.Ordinal = GetProcAddress_fixup(hModule, (char *)(pimp_by_name->Name));
		}
		VERB(printf("name: %s\n", fnname));
		assert(pthunkBind->u1.Ordinal != 0);
	}

	return 0;
}

static int pe_dlmmap(Obj_Entry * obj, PEImage * image,
		 const IMAGE_NT_HEADERS * hdr_pe, const void * hdr_buf, size_t hdr_size)
{
	size_t imgsize;
	ssize_t nbytes;

	size_t data_off;
	size_t data_size;
	char * data_vaddr;
	char * data_vlimit;
	size_t data_memsz;

	char * base_vaddr, * base_vlimit, * image_base;

	IMAGE_SECTION_HEADER * psect;
	IMAGE_SECTION_HEADER * psectinit, * psectfini;

	imgsize = hdr_pe->OptionalHeader.SizeOfImage;
	psectinit = (IMAGE_SECTION_HEADER *)(&hdr_pe[1]);
	psectfini = (psectinit + hdr_pe->FileHeader.NumberOfSections);

	image_base = (char *)hdr_pe->OptionalHeader.ImageBase;
	obj->relocbase = (char *)pe_alloc(image_base, imgsize);
	assert(obj->relocbase != NULL);
	obj->delta = (obj->relocbase - image_base);
	memset(obj->relocbase, 0, imgsize);
	memcpy(obj->relocbase, hdr_buf, hdr_size);

	base_vaddr = obj->relocbase;
	base_vlimit = obj->relocbase + imgsize;
	for (psect = psectinit; psect < psectfini; psect++) {
		data_off = psect->PointerToRawData;
		data_size = psect->SizeOfRawData;
		data_memsz = psect->Misc.VirtualSize;
		data_vaddr = obj->relocbase + psect->VirtualAddress;
		data_vlimit = (data_vaddr + data_memsz);

		VERB(printf("data_size %u, data_memsz %u %X\n", data_size, data_memsz, psect->Characteristics));

		assert(data_vaddr >= base_vaddr && data_vaddr < base_vlimit);
		assert(data_vlimit >= base_vaddr && data_vlimit <= base_vlimit);

		nbytes = image->pread(data_vaddr, data_size, data_off);
		if (nbytes != data_size) {
			pe_free(obj->relocbase, obj->relocsize);
			obj->relocbase = 0;
			return -1;
		}

		if (data_size < data_memsz) {
			VERB(printf("data_size %u, data_memsz %u\n", data_size, data_memsz));
			memset(data_vaddr + data_size, 0, data_memsz - data_size);
		}
	}

	obj->relocsize = imgsize;
	if (hdr_pe->OptionalHeader.AddressOfEntryPoint != 0) {
		if (hdr_pe->FileHeader.Characteristics & IMAGE_FILE_DLL)
			obj->dllentry = (obj->relocbase + hdr_pe->OptionalHeader.AddressOfEntryPoint);
		else
			obj->exeentry = (obj->relocbase + hdr_pe->OptionalHeader.AddressOfEntryPoint);
	}

	printf("DllCharacteristics: %x\n", hdr_pe->OptionalHeader.DllCharacteristics);
	printf("Characteristics: %x\n", hdr_pe->FileHeader.Characteristics);
	printf("LoaderFlags: %x\n", hdr_pe->OptionalHeader.LoaderFlags);

	obj->expsize = hdr_pe->OptionalHeader.DataDirectory[0].Size;
	obj->exptable = (PIMAGE_EXPORT_DIRECTORY)(obj->relocbase + hdr_pe->OptionalHeader.DataDirectory[0].VirtualAddress);

	obj->impsize = hdr_pe->OptionalHeader.DataDirectory[1].Size;
	obj->imptable = (PIMAGE_IMPORT_DESCRIPTOR)(obj->relocbase + hdr_pe->OptionalHeader.DataDirectory[1].VirtualAddress);

	obj->ressize = hdr_pe->OptionalHeader.DataDirectory[2].Size;
	obj->restable = (PIMAGE_RESOURCE_DIRECTORY)(obj->relocbase + hdr_pe->OptionalHeader.DataDirectory[2].VirtualAddress);

	obj->relsize = hdr_pe->OptionalHeader.DataDirectory[5].Size;
	obj->reltable = (obj->relocbase + hdr_pe->OptionalHeader.DataDirectory[5].VirtualAddress);

	return 0;
}

void DumpResource(Obj_Entry * obj)
{
	PIMAGE_RESOURCE_DIRECTORY dir = obj->restable;
#define XX(field) printf("%s: %x\n", #field, dir->field)
	XX(Characteristics);
	XX(TimeDateStamp);
	XX(MajorVersion);
	XX(MinorVersion);
	XX(NumberOfNamedEntries);
	XX(NumberOfIdEntries);
#undef XX

	PIMAGE_RESOURCE_DIRECTORY_ENTRY dirp = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(dir + 1);
	for (int i = 0; i < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; i++) {
		printf("Name: %x\n", dirp->Name);
		printf("OffsetToData: %x\n", dirp->OffsetToData);
	}

	return;
}

Obj_Entry * peLoadImage(PEImage * image)
{
	int error;
	Obj_Entry * obj;
	size_t nsect;
	ssize_t nbytes;
	const IMAGE_NT_HEADERS * hdr_pe;
	PIMAGE_IMPORT_DESCRIPTOR imp_pe, imp_fini;

	union {
		IMAGE_DOS_HEADER hdr;
		char buf[PAGESIZE];
	}u;

	nbytes = image->pread(u.buf, PAGESIZE, 0);
	if (nbytes == -1) {
		VERB(printf("image->pread\n"));
		return NULL;
	}

	if ((size_t) nbytes < sizeof(u.hdr)) {
		VERB(printf("sizeof(u.hdr) = %u\n", nbytes));
		return NULL;
	}

	if (u.hdr.e_magic != IMAGE_DOS_SIGNATURE) {
		VERB(printf("u.hdr.e_magic = %x\n", u.hdr.e_magic));
		return NULL;
	}

	if (u.hdr.e_lfanew + sizeof(*hdr_pe) > nbytes) {
		VERB(printf("u.hdr.e_lfanew = %u\n", u.hdr.e_lfanew));
		return NULL;
	}

	hdr_pe = (const IMAGE_NT_HEADERS *)(u.buf + u.hdr.e_lfanew);
	if (hdr_pe->Signature != IMAGE_NT_SIGNATURE) {
		VERB(printf("hdr_pe->Signature = %x\n", hdr_pe->Signature));
		return NULL;
	}

	nsect = hdr_pe->FileHeader.NumberOfSections;
	if (u.hdr.e_lfanew + sizeof(*hdr_pe) +  nsect * sizeof(IMAGE_SECTION_HEADER) > nbytes) {
		VERB(printf("nsect = %u\n", nsect));
		return NULL;
	}

	obj = (Obj_Entry *)malloc(sizeof(Obj_Entry));
	if (obj == NULL) {
		VERB(printf("malloc\n"));
		return NULL;
	}

	memset(obj, 0, sizeof(*obj));
	size_t hdr_size = u.hdr.e_lfanew + sizeof(*hdr_pe) + nsect * sizeof(IMAGE_SECTION_HEADER);

	if (0 != pe_dlmmap(obj, image, hdr_pe, u.buf, hdr_size)) {
		free(obj);
		return NULL;
	}

	imp_fini = (PIMAGE_IMPORT_DESCRIPTOR)(((char *)obj->imptable) + obj->impsize);

	for (imp_pe = obj->imptable; imp_pe < imp_fini; imp_pe++) {
		PIMAGE_THUNK_DATA pThunkBind, pThunkKeep;
		pThunkBind = (PIMAGE_THUNK_DATA)(obj->relocbase + imp_pe->FirstThunk);
		pThunkKeep = pThunkBind;

		if (imp_pe->Name == 0) {
			VERB(printf("imp_pe->Name\n"));
			break;
		}

		if (imp_pe->DUMMYUNIONNAME.OriginalFirstThunk != 0)
			pThunkKeep = (PIMAGE_THUNK_DATA)(obj->relocbase + imp_pe->DUMMYUNIONNAME.OriginalFirstThunk);

		error = BindThunkArray(obj, obj->relocbase + imp_pe->Name, pThunkBind, pThunkKeep);

		if (error != 0) {
			pe_free(obj->relocbase, obj->relocsize);
			free(obj);
			return NULL;
		}
	}

	char * reltbl = obj->reltable;
	while (reltbl < (obj->reltable + obj->relsize)) {
		LPDWORD where;
		char * reloc_addr;
		LPWORD rel, rel_limit;
		PIMAGE_BASE_RELOCATION reloc_blk;

	   	reloc_blk = (PIMAGE_BASE_RELOCATION)reltbl;
		reloc_addr = (obj->relocbase + reloc_blk->VirtualAddress);

		rel_limit = (LPWORD)(reltbl + reloc_blk->SizeOfBlock);
		for (rel = (LPWORD)(reltbl + sizeof(*reloc_blk)); rel < rel_limit; rel++) {
			switch (*rel >> 12) {
				case IMAGE_REL_BASED_HIGHLOW:
					where = (LPDWORD)(reloc_addr + (*rel & 0xFFF));
					*where += obj->delta;
					break;

				case IMAGE_REL_BASED_ABSOLUTE:
					VERB(printf("IMAGE_REL_BASED_ABSOLUTE\n"));
					break;

				default:
					printf("unkown rel: %x\n", (*rel >> 12));
					break;
			}
		}

		if (reloc_blk->VirtualAddress == 0) {
			VERB(printf("reloc_blk->VirtualAddress"));
			break;
		}

		assert(reloc_blk->SizeOfBlock > 0);
		reltbl += reloc_blk->SizeOfBlock;
	}

	//DumpResource(obj);
	if (peCallDllEntry(obj, DLL_PROCESS_ATTACH))
		return obj;

	pe_free(obj->relocbase, obj->relocsize);
	free(obj);
	return NULL;
}

typedef unsigned int BOOL;
#define TRUE 1
#define FALSE 0
typedef BOOL __stdcall DllMain(void * hinst, DWORD fdwReason, void * lpvReserved);

BOOL peCallDllEntry(Obj_Entry * obj, DWORD fdwReason)
{
	DllMain * dll_init;

	printf("peCallDllEntry: %p\n", obj->dllentry);

	if (obj->dllentry == NULL)
		return TRUE;

	dll_init = (DllMain *)obj->dllentry;
	return dll_init(obj->relocbase, fdwReason, NULL);
}

void peCallMainEntry(Obj_Entry * obj)
{
	void (* pe_init)(void);

	printf("peCallMainEntry: %p\n", obj->exeentry);

	if (obj->exeentry == NULL)
		exit(-1);

	pe_init = (void (*) (void))obj->exeentry;
	return pe_init();
}

void * peGetProcAddress(Obj_Entry * obj, const char * name)
{
	int i;
	LPDWORD strtab;
	LPDWORD func_addr;
	unsigned short * ordi_addr;
	PIMAGE_EXPORT_DIRECTORY expdir;

	expdir = obj->exptable;
	if (obj->expsize < sizeof(*expdir) ||
			obj->exptable == NULL) {
		VERB(printf("no export function table\n"));
		return NULL;
	}

	strtab = (LPDWORD)(obj->relocbase + expdir->AddressOfNames);
	func_addr = (LPDWORD)(obj->relocbase + expdir->AddressOfFunctions);
	ordi_addr = (unsigned short *)(obj->relocbase + expdir->AddressOfNameOrdinals);

	if (name < (char *)0x10000) {
		DWORD index = (size_t)(name);
		VERB(printf("peGetProcAddressByIndex %s\n", index));
		return (obj->relocbase + func_addr[index]);
	}

	for (i = 0; i < expdir->NumberOfNames; i++) {
		char * retval = 0;
		if (0 != strcmp(obj->relocbase + strtab[i], name))
			continue;
		VERB(printf("peGetProcAddressByName %s\n", name));
		VERB(printf("peGetProcAddressByName %x\n", func_addr[ordi_addr[i]]));
		retval = (obj->relocbase + func_addr[ordi_addr[i]]);
		return retval;
	}

	return NULL;
}

