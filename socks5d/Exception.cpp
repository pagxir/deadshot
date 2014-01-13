#include "stdafx.h"
#include <time.h>
#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>

#include "Exception.h"

static char CrashNamePrefix[512] = "sdserver_";
static char SnapshotPrefix[1024] = "snapshot-";
static char * pDumpNamePrefix = CrashNamePrefix;

typedef BOOL WriteDump(HANDLE hProcess, DWORD ProcessId,
					   HANDLE hFile, MINIDUMP_TYPE DumpType,
					   PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
					   PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
					   PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

typedef WriteDump * MiniDumpWriteDump_PTR;

static BOOL LoadDbghelp(HMODULE *phModule, FARPROC *pMiniDumpWriteDump)
{
	FARPROC MiniDumpWriteDump = NULL;
	HMODULE hModule = LoadLibrary("dbghelp.dll");
	if (hModule == NULL) {
		return FALSE;
	}

	MiniDumpWriteDump = GetProcAddress(hModule, "MiniDumpWriteDump");
	if (pMiniDumpWriteDump != NULL)	{
		*pMiniDumpWriteDump = MiniDumpWriteDump;
		*phModule = hModule;
		return TRUE;
	}

	FreeLibrary(hModule);
	return FALSE;
}

BOOL CreateMiniDump(const char * prefix, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	BOOL bSuccess = FALSE;
	HMODULE hModule = NULL;
	char szFile[MAX_PATH + 1] = {0};
	MINIDUMP_EXCEPTION_INFORMATION mei;
	MiniDumpWriteDump_PTR pfnMiniDumpWriteDump;

	if ( !LoadDbghelp(&hModule, (FARPROC *)&pfnMiniDumpWriteDump) ) {
		OutputDebugString("Load Dbghelp Failure!\n");
		return FALSE;
	}
	
	mei.ThreadId = GetCurrentThreadId();
	mei.ClientPointers = TRUE;
	mei.ExceptionPointers = ExceptionInfo;

	_snprintf(szFile, MAX_PATH, ".\\%s%u.dmp", prefix, time(NULL));
	HANDLE hFile = CreateFile(szFile, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

	if (INVALID_HANDLE_VALUE != hFile) {
		(*pfnMiniDumpWriteDump)(GetCurrentProcess(), GetCurrentProcessId(),
			hFile, MiniDumpNormal, ExceptionInfo? &mei: NULL, NULL, NULL);
		CloseHandle(hFile);
		bSuccess = TRUE;
	}

	FreeLibrary(hModule);
	return bSuccess;
}

BOOL WriteMiniDumpSnapshot(const char * prefix)
{
	strncpy(SnapshotPrefix, prefix, sizeof(SnapshotPrefix));
	pDumpNamePrefix = SnapshotPrefix;
	RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
	pDumpNamePrefix = CrashNamePrefix;
	return TRUE;
}

static LONG WINAPI SDClient_UnhandledExceptionFilter(struct _EXCEPTION_POINTERS * ExceptionInfo)
{
	DWORD flags = ExceptionInfo->ExceptionRecord->ExceptionFlags;

	OutputDebugString("SDServer meet unhandled SEH exception! Quit!\n");
	CreateMiniDump(pDumpNamePrefix, ExceptionInfo);
	OutputDebugString("SDServer Save MiniDump Completed!\n");
	
	::SetErrorMode(SEM_NOGPFAULTERRORBOX);
	::ExitProcess(1);
	
	return EXCEPTION_EXECUTE_HANDLER;
	//return (flags == 0? EXCEPTION_CONTINUE_EXECUTION: EXCEPTION_EXECUTE_HANDLER);
}

void SetExceptionDumpHandle(const char * name)
{
	strncpy(CrashNamePrefix, name, sizeof(CrashNamePrefix) - 1);
	::SetUnhandledExceptionFilter(SDClient_UnhandledExceptionFilter);
}
