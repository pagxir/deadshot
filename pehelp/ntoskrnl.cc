#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(__POSIX__)
#include <pthread.h>
#endif
#include <string>
#include <vector>
#include <ddk/ntddk.h>
#include <windows.h>

#include "dllwrap.h"

#ifndef WINAPI
#define WINAPI __attribute__((__stdcall__))
#endif

#define MATCH2(fNAME, proxy) \
	if ( !strcmp(fNAME, name) ){ *pfunc = (void*)proxy; return 0; }

VOID WINAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString,
		PCWSTR SourceString)
{
	int i = sizeof(UNICODE_STRING);
	printf("RtlInitUnicodeString: %dd %dd %pp %ws %d\n",
			DestinationString->Length,
			DestinationString->MaximumLength,
			DestinationString->Buffer,
			SourceString, lstrlenW(SourceString));
	DestinationString->Length = lstrlenW(SourceString);
	DestinationString->MaximumLength = 256;
	DestinationString->Buffer = new WCHAR[256];
	memset(DestinationString->Buffer, 0, 512);
	memcpy(DestinationString->Buffer, SourceString,
			DestinationString->Length * 2);
}

static size_t __device_size = 0;
PDEVICE_OBJECT __device_base = NULL;

VOID IoCompleteRequest(PIRP Irp, CCHAR PriorityBoost)
{
	printf("IoCompleteRequest: %p %x\n", Irp, PriorityBoost);
}

NTSTATUS IoCreateDevice(PDRIVER_OBJECT DriverObject,
		ULONG DeviceExtensionSize,
		PUNICODE_STRING DeviceName,
		DEVICE_TYPE DeviceType,
		ULONG DeviceCharacteristics,
		BOOLEAN Exclusive,
		PDEVICE_OBJECT *DeviceObject)
{
	printf("DriverObject: %pp\n", DriverObject);
	printf("DeviceExtensionSize: %u\n", DeviceExtensionSize);
	printf("DeviceName: %ws\n", DeviceName->Buffer);
	printf("DeviceType: %xx\n", DeviceType);
	printf("DeviceCharacteristics: %xx\n", DeviceCharacteristics);
	printf("Exclusive: %xx\n", Exclusive);

	PDEVICE_OBJECT p_dev_obj = (PDEVICE_OBJECT)new char[sizeof(p_dev_obj[0]) + DeviceExtensionSize];
	*DeviceObject = p_dev_obj;
	memset(p_dev_obj, 0, sizeof(p_dev_obj[0]) + DeviceExtensionSize);
	__device_base = p_dev_obj;
	__device_size = sizeof(p_dev_obj[0]) + DeviceExtensionSize;
	p_dev_obj->DeviceExtension = &p_dev_obj[1];
	DriverObject->DeviceObject = p_dev_obj;
	printf("IoCreateDevice: %p\n", p_dev_obj);
	return STATUS_SUCCESS;
}

NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName,
		PUNICODE_STRING DeviceName)
{
	printf("IoCreateSymbolicLink: %ws, %ws\n",
			SymbolicLinkName->Buffer, DeviceName->Buffer);
	return STATUS_SUCCESS;
}

NTSTATUS IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName)
{
	printf("IoDeleteSymbolicLink: %ws\n", SymbolicLinkName->Buffer);
	return STATUS_SUCCESS;
}

VOID IoDeleteDevice(PDEVICE_OBJECT DeviceObject)
{
	printf("IoDeleteDevice: %p\n", DeviceObject);
}

int ntoskrnl_GetProcAddress(const char *name, void **pfunc)
{
	MATCH2("RtlInitUnicodeString", RtlInitUnicodeString);
	MATCH2("IoCreateSymbolicLink", IoCreateSymbolicLink);
	MATCH2("IoDeleteSymbolicLink", IoDeleteSymbolicLink);
	MATCH2("IoCreateDevice", IoCreateDevice);
	MATCH2("IoDeleteDevice", IoDeleteDevice);
	MATCH2("IofCompleteRequest", IoCompleteRequest);
	printf("fixme: %s@ntoskrnl.exe\n", name);
	return -1;
}

void ntoskrnl_dump(const void * buf, size_t len)
{
	const unsigned char * p = (const unsigned char *)buf;
	printf("DriverObject: ");
	for (int i = 0; i < len; i++)
		printf("%02x", *p++ );
	printf("\n");

	PDEVICE_OBJECT a;
	printf("DeviceObject(%d): ", sizeof(a[0]));
	p = (const unsigned char *)__device_base;
	for (int i = 0; i < __device_size; i++)
		printf("%02x", *p++);
	printf("\n");

	const PDRIVER_OBJECT __drive_obj = (const PDRIVER_OBJECT)buf;
#define XX(a) printf("%s: %x\n", #a, __drive_obj->a);
	XX(Type);
	XX(Size);
	XX(DeviceObject);
	XX(Flags);
	XX(DriverStart);
	XX(DriverSize);
	XX(DriverSection);
	XX(DriverExtension);
	XX(DriverName);
	XX(HardwareDatabase);
	XX(FastIoDispatch);
	XX(DriverInit);
	XX(DriverStartIo);
	XX(DriverUnload);
	XX(MajorFunction);
#undef XX

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		printf("IRP_MJ_MAXINUM_FUNCTION-%d: %p\n", i, __drive_obj->MajorFunction[i]);

	printf("DeviceObject\n");

#define XX(a) printf("%s: %x\n", #a, __device_base->a);
	XX(Type);
	XX(Size);
	XX(ReferenceCount);
	XX(DriverObject);
	XX(NextDevice);
	XX(AttachedDevice);
	XX(CurrentIrp);
	XX(Timer);
	XX(Flags);
	XX(Characteristics);
	XX(Vpb);
	XX(DeviceExtension);
	XX(DeviceType);
	XX(StackSize);
	XX(Queue.ListEntry);
	XX(Queue.Wcb);
	XX(ActiveThreadCount);
	XX(SecurityDescriptor);
	XX(DeviceLock);
	XX(SectorSize);
	XX(Spare1);
	XX(DeviceObjectExtension);
	XX(Reserved);
#undef XX


	printf("DeviceExtension:\n");
	p = (const unsigned char *)&__device_base[1];
	for (int i = 0; i < __device_size - (int)sizeof(a[0]); i++)
		printf("%02x", *p++);
	printf("\n");

#define YY(f) printf("%s: %d\n", #f, f);
	YY(IRP_MJ_CREATE);
	YY(IRP_MJ_CLOSE);
	YY(IRP_MJ_DEVICE_CONTROL);
#undef YY
}

static int ntoskrnl_base = 0;
void * __g_ntoskrnl = &ntoskrnl_base;
