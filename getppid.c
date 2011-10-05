#include <stdio.h>
#include <windows.h>

#define ProcessBasicInformation 0

typedef struct {
	DWORD ExitStatus;
	DWORD PebBaseAddress;
	DWORD AffinityMask;
	DWORD BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
LONG (WINAPI *NtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

pid_t getppid(pid_t pid)
{
	LONG status;
	HANDLE hProcess;
	pid_t ppid = (pid_t)-1;
	PROCESS_BASIC_INFORMATION pbi;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (hProcess == NULL)
		return (pid_t)-1;

	status = NtQueryInformationProcess(hProcess,
			ProcessBasicInformation, (PVOID)&pbi,
			sizeof(PROCESS_BASIC_INFORMATION), NULL);
	CloseHandle(hProcess);

	if (status == 0x00000000)
		ppid = pbi.InheritedFromUniqueProcessId;

	return ppid;
}


int main(int argc, char *argv[])
{
	pid_t pid;

	if (argc < 2) {
		printf("Usage:\n\nparent.exe ProcId\n");
		return 0;
	}

	sscanf(argv[1], "%lu", &pid);
	*(void **)&NtQueryInformationProcess = (void *)GetProcAddress(
			GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess)
		printf("Parent PID for %lu is %lu\n", pid, getppid(pid));

	return 0;
}

