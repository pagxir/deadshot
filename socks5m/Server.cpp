#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <dbghelp.h>
#include <string>

#include "Network.h"

#define NDSSERVER "NDSServer"

static HANDLE gNSMainEvent;
static HANDLE gNSMainHandle;
static SERVICE_STATUS ssStatus;
static SERVICE_STATUS_HANDLE sshStatusHandle;
typedef BOOL WINAPI FN_MiniDumpWriteDump(HANDLE,
		DWORD, HANDLE, DWORD, LPVOID, LPVOID, LPVOID);

static void CALLBACK ServerCtrl(DWORD dwCtrlCode)
{
	char buf[1024];

	switch (dwCtrlCode) 
	{
		case SERVICE_CONTROL_STOP:
			NDSQuitCall();
			WaitForSingleObject(gNSMainHandle, INFINITE);
			ssStatus.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(sshStatusHandle, &ssStatus);
			break;

		case SERVICE_CONTROL_INTERROGATE:
			SetServiceStatus(sshStatusHandle, &ssStatus);
			break;

		default:
			sprintf(buf, "ServerCtrl: invalid CtrlCode: 0x%08X", dwCtrlCode);
			OutputDebugString(buf);
			break;
	}
}

void CALLBACK ServerWrapper(DWORD argc, LPTSTR * argv)
{
	sshStatusHandle = RegisterServiceCtrlHandler(TEXT(NDSSERVER), ServerCtrl);
	memset(&ssStatus, 0, sizeof(ssStatus));
	ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP| SERVICE_ACCEPT_PAUSE_CONTINUE;

	ssStatus.dwCurrentState = SERVICE_START_PENDING;
	SetServiceStatus(sshStatusHandle, &ssStatus);
	SetEvent(gNSMainEvent);
}

static SERVICE_TABLE_ENTRY service_table_entrys[] = 
{
	{ TEXT(NDSSERVER), ServerWrapper },
	{ NULL, NULL }
};

void ShowInformation(void)
{
	const char compile_info[] = __DATE__ " " __TIME__;
	const char version_info[] = "$Id: DeliveryClient.cpp,v 1.40 2010/04/14 10:32:04 peiguoxing Exp $";	
	printf("\t compile: %s\n", compile_info);
	printf("\t version: %s\n", version_info);
	exit(-1);
}

DWORD CALLBACK NSMainThread(LPVOID lParam)
{
	HANDLE hEvent = (HANDLE)lParam;
	WaitForSingleObject(hEvent, INFINITE);

	ssStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(sshStatusHandle, &ssStatus);
	return NDSMainCall(FALSE);
}

LONG WINAPI CrashDumpHandle(struct _EXCEPTION_POINTERS * lpExceptionInfo)
{
	BOOL success;
	TCHAR PathName[64];
	HANDLE hFile = NULL;
	HMODULE hModule = NULL;
	MINIDUMP_EXCEPTION_INFORMATION mei;
	FN_MiniDumpWriteDump * fnMiniDumpWriteDump = NULL;
	LONG  result = EXCEPTION_EXECUTE_HANDLER;

	sprintf(PathName, "socks5m_%u.dmp", time(NULL));
	SetErrorMode( SEM_NOGPFAULTERRORBOX );

	hFile = CreateFile(PathName, GENERIC_WRITE, 0, 
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return 0L;

	do {
		mei.ThreadId = GetCurrentThreadId();
		mei.ClientPointers = FALSE;
		mei.ExceptionPointers = lpExceptionInfo;

		hModule = LoadLibrary("dbghelp.dll");
		if (hModule == NULL)
			break;

		FARPROC fnAddress = GetProcAddress(hModule, "MiniDumpWriteDump");
		fnMiniDumpWriteDump = (FN_MiniDumpWriteDump *)(fnAddress);
		success = fnMiniDumpWriteDump(GetCurrentProcess(),
				GetCurrentProcessId(), hFile, MiniDumpNormal, &mei, NULL, NULL);
		FreeLibrary(hModule);
	} while ( 0 );

	CloseHandle(hFile);
	return lpExceptionInfo->ExceptionRecord->ExceptionFlags? 0L: -1;
}

int main(int argc, char * argv[])
{
	DWORD id;
	BOOL  success = FALSE;
	SetUnhandledExceptionFilter(CrashDumpHandle);

	if (argc > 1 && !strcmp(argv[1], "--version"))
		ShowInformation();

	if (argc > 1 && strcmp(argv[1], "--debug"))
		return -1;

	gNSMainEvent = CreateEvent(NULL, FALSE, FALSE, "Global\\socks5m");
	gNSMainHandle = CreateThread(NULL, 0, NSMainThread, gNSMainEvent, 0, &id);
	printf("ThreadId: %d\n", id);
	success = argc > 1? TRUE: StartServiceCtrlDispatcher(service_table_entrys);
	SetEvent(gNSMainEvent);
	WaitForSingleObject(gNSMainHandle, INFINITE);
	CloseHandle(gNSMainHandle);

	return success? 0: GetLastError();
}

