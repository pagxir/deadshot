#include "stdafx.h"
#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <windows.h>

#include "Utils.h"
#include "Config.h"

#include "SDServer.h"
#include "Exception.h"

#define EVENT_NAME ("Global\\EPol_SDServer.Event")

static char RequstName[256] = "Reload";
static volatile DWORD lastStatus = SERVICE_RUNNING;
static volatile SERVICE_STATUS_HANDLE sshStatusHandle;

static int ControlEvent(const char * event)
{
	HANDLE hEvent;
	hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, EVENT_NAME);
	strncpy(RequstName, event, sizeof(RequstName));
	SetEvent(hEvent);
	CloseHandle(hEvent);
	return 0;
}

static BOOL UpdateStatus(SERVICE_STATUS_HANDLE handle, DWORD status)
{
	SERVICE_STATUS ssStatus;
	
	if (handle != 0) {
		memset(&ssStatus, 0, sizeof(ssStatus));
		ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP| SERVICE_ACCEPT_PAUSE_CONTINUE;
		ssStatus.dwCurrentState = status;
		
		return SetServiceStatus(handle, &ssStatus);
	}

	return FALSE;
}

static DWORD CALLBACK _DeliveryWrapper(LPVOID lParam)
{
	HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, EVENT_NAME);
	Delivery(hEvent, RequstName, sizeof(RequstName));
	CloseHandle(hEvent);

	UpdateStatus(sshStatusHandle, SERVICE_STOPPED);
	return 0;
}

static void CALLBACK _ControlHandle(DWORD dwCtrlCode)
{
	switch (dwCtrlCode) 
	{
	case SERVICE_CONTROL_STOP:
		UpdateStatus(sshStatusHandle, SERVICE_STOPPED);
		sshStatusHandle = 0;
		ControlEvent("Quit");
		break;

	case SERVICE_CONTROL_PAUSE:
		UpdateStatus(sshStatusHandle, lastStatus = SERVICE_PAUSED);
		ControlEvent("Reload");
		break;

	case SERVICE_CONTROL_CONTINUE:
		UpdateStatus(sshStatusHandle, lastStatus = SERVICE_RUNNING);
		break;

	case SERVICE_CONTROL_INTERROGATE:
		UpdateStatus(sshStatusHandle, lastStatus);
		break;

	default:
		RT_ASSERT((dwCtrlCode == SERVICE_CONTROL_STOP || dwCtrlCode == SERVICE_CONTROL_INTERROGATE),
			"Invaliadate Service Control Code");
		break;
	}
}

static void CALLBACK _Daemonize(DWORD dwArgc, LPTSTR *lpszArgv)
{
    sshStatusHandle = RegisterServiceCtrlHandler(TEXT("SAAgent"), _ControlHandle);
	UpdateStatus(sshStatusHandle, lastStatus);
}

static SERVICE_TABLE_ENTRY _DispatchTable[] =
{
	{ TEXT("SAAgent"), _Daemonize },
	{ NULL, NULL }
};

static int LogInitailize(void)
{
	int len;
	char buf[1024];
	len = GetModuleFileName(NULL, buf, sizeof(buf));
	DS_ASSERT(len > 0 && len <= sizeof(buf));

	char * pslash = strrchr(buf, '\\');
	DS_ASSERT(pslash != NULL);

	*pslash = 0;
	SetCurrentDirectory(buf);
	strncat(buf, "\\SDServer.ini", sizeof(buf));

	return 0;
}

int main(int argc, char *argv[])
{
	WSADATA data;
	BOOL bSuccess;
	DWORD ThreadId;
	DWORD LastError = 0;
	HANDLE hDeliveryThread;

	while (argc > 1) {
		if (strcmp(argv[1], "--debug") == 0) {
			break;
		}

		if (strcmp(argv[1], "--ver") == 0) {
			fprintf(stderr, "source version: 2011-03-09\n");
			return 0;
		}

		if (strcmp(argv[1], "--version") == 0) {
			fprintf(stderr, "source version: 2011-03-09\n");
			return 0;
		}

		return 0;
	}

	srand(time(NULL));
	LogInitailize();
	CfgInitialize("SDServer.ini");
	WSAStartup(0x101, &data);

	SetExceptionDumpHandle("sdserver-");
	hDeliveryThread = CreateThread(NULL, 0, _DeliveryWrapper, NULL, 0, &ThreadId);

	if (argc < 2) {
		bSuccess = StartServiceCtrlDispatcher(_DispatchTable);
		if (bSuccess == FALSE) {
			DWORD state;
			LastError = GetLastError();

			do {
				ControlEvent("Quit");
				state = WaitForSingleObject(hDeliveryThread, 1000);
			} while (state == WAIT_TIMEOUT);

			printf("Service start failue!\n");
		}
		WaitForSingleObject(hDeliveryThread, INFINITE);
		CloseHandle(hDeliveryThread);
		return LastError;
	}

	WaitForSingleObject(hDeliveryThread, INFINITE);
	CloseHandle(hDeliveryThread);
	WSACleanup();
	return 0;
}
