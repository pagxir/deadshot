#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <windows.h>
#include <ddk/ntddk.h>

#include "pehlp.h"


static void DummyCall(void)
{
	/* a function stub *
	 * nothing need to do
	 */
}

static char shellcode_40700E[] = {
	0xFA, 0xB9, 0x41, 0x00, 0x01, 0xC0, 0x0F, 0x30,
	0x33, 0xDB, 0xB9, 0x42, 0x00, 0x01, 0xC0, 0x90,
	0x83, 0xC3, 0x01, 0x0F, 0x32, 0x85, 0xC0, 0x78,
	0xF7, 0xFB, 0xC3
};

static DWORD kpi_40700E = (DWORD)DummyCall;

static int KPIAlloc(void)
{
    char * kpi_base = (char *)VirtualAlloc(NULL, 4096,
		   	MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (kpi_base == NULL) {
		printf("VirtualAlloc return NULL (LastError = %d)\n", GetLastError());
		exit(0);
    }
	kpi_40700E = (DWORD)kpi_base;
	memcpy(kpi_base, shellcode_40700E, sizeof(shellcode_40700E));
	kpi_base += sizeof(shellcode_40700E);
    return 0;
}

void dump_hex(const void * user_buf, size_t len)
{
	const unsigned char * p = (const unsigned char *)user_buf;
	while (len-- > 0)
		printf("%02x", *p++);
	printf("\n");
}

void ntoskrnl_dump(const void * buf, size_t len);
typedef NTSTATUS __stdcall IrpDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
typedef NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

void *__this_handle = NULL;

int setup_ldt();

extern size_t _argcnt;
extern char **_arglist;
#if 1
static unsigned char user_buf[] = {
	0x00, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xD0, 0x07, 0x00, 0x00,
   	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0E, 0x70, 0x40, 0x00
};
#else
static DWORD user_buf[] = {
   	0x0057A288, 0x00434AB8
};
#endif


extern PDEVICE_OBJECT __device_base;

int main(int argc, char *argv[])
{
    int i;
    typedef int SPT();
    DriverEntry *entry = NULL;
    void *PEFile = NULL;

    setup_ldt();
	DRIVER_OBJECT driver_object;
	memset(&driver_object, 0, sizeof(driver_object));

    _argcnt = argc - 1;
    _arglist = (argv + 1);

	IRP irp = {0};
	struct _IO_STACK_LOCATION location = {0};
	location.MajorFunction = 0;
	//irp.Overlay.DUMMYSTRUCTNAME.DUMMYUNIONNAME.CurrentStackLocation = &location;
	irp.Tail.Overlay.CurrentStackLocation = &location;

#if 1
	const char * netsh_path = "H:\\RTMTools\\pehelp\\RTCore32.sys";

	if (PEFile = peaux_LoadLibrary(netsh_path)) {
	   	__this_handle = PEFile;
	   	printf("entry: %p\n", entry);
	   	if (entry = (DriverEntry *)peaux_GetEntryPoint(PEFile)) {
		   	printf("entry: %p %p\n", entry, &driver_object);
		   	int code = entry(&driver_object, NULL);
		   	ntoskrnl_dump(&driver_object, sizeof(driver_object));
			IrpDispatch * pDispatch = driver_object.MajorFunction[0];
		   	printf("Create: %d\n", pDispatch(__device_base, &irp));
		   	location.MajorFunction = 14;
			//irp.UserBuffer = user_buf;
			memcpy(user_buf + 24, &kpi_40700E, 4);
			irp.AssociatedIrp.SystemBuffer = user_buf;
			location.Parameters.DeviceIoControl.IoControlCode = 0x80002020;
			location.Parameters.DeviceIoControl.InputBufferLength = sizeof(user_buf);
			location.Parameters.DeviceIoControl.OutputBufferLength = sizeof(user_buf);
			dump_hex(user_buf, sizeof(user_buf));
			int err_code = pDispatch(__device_base, &irp);
			dump_hex(user_buf, irp.IoStatus.Information);
		   	printf("Control: %x %d %d\n", err_code, user_buf[0], user_buf[1]);
			printf("Information: %d\n", irp.IoStatus.Information);
			printf("Status: %d\n", irp.IoStatus.Status);
		   	location.MajorFunction = 2;
		   	printf("Close: %d\n", pDispatch(__device_base, &irp));
			driver_object.DriverUnload(&driver_object);
	   	}
	   	peaux_FreeLibrary(PEFile);
   	}
#endif
	return 0;
#if 0
#if 1
    for (i=1; i<argc; i++){
        if (PEFile = peaux_LoadLibrary("C:\\Windows\\system32\\netsh.exe")){
            __this_handle = PEFile;
            if (entry=(SPT*)peaux_GetEntryPoint(PEFile)){
                printf("entry: %p\n", entry);
                entry();
            }
            peaux_FreeLibrary(PEFile);
        }
    }
    printf("Exiting\n");
#else
    printf("++++++++entry: %p\n", PEFile);
    for (i=1; i<argc; i++){
        if (PEFile = peaux_LoadLibrary(argv[i])){
            printf("image: %p\n", PEFile);
            if (entry=(SPT*)peaux_GetProcAddress(PEFile, "auxMain")){
                printf("entry: %p\n", entry);
                entry(argc, argv);
            }
            peaux_FreeLibrary(PEFile);
        }
    }
#endif
#endif
    return 0;
}
