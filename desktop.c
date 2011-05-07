#if 0
/*
Get information function.
--list pid
--list station
--list desktop
--list desktop@<station>

Set information function.
--wait <seconds|detach> 
--session <session>
--desktop <desktop>
--station <station>
--process /path/to/program

Execute function.
--switch desktop
--setting station
--setting desktop
--create session 
--create desktop
--create process
--system  run as system right
--deamon  run as services and wait for exist.
--help

*/

#endif
 
 
 
使用方法(假设程序名称是desktop.exe):
desktop.exe --prog-name notepad.exe --sleep-seconds 4 --new-process desk0 --switch-desktop desk0
编译好的文件
#include <stdio.h>
#include <windows.h>
#include <Wtsapi32.h>
#include <Tlhelp32.h>

#define abortif(cond) \
	do { \
		if (cond) { \
			printf("exp %s, file %s, line %d\n", #cond, __FILE__, __LINE__); \
			exit( 0 ); \
		} \
	} while ( 0 )

static int __detach_desktop = 0;
static int __sleep_seconds  = 16;
static const char * __prog_name = NULL;

typedef DWORD WINAPI FWTSGETACTIVECONSOLESESSIONID(void);
static FWTSGETACTIVECONSOLESESSIONID * fnWTSGetActiveConsoleSessionId = NULL;

static DWORD list_active_console()
{
	DWORD wtsid = 0;
	DWORD Count = 0;
	BOOL  bResult = FALSE;
	FARPROC fnProcAddress;
	DWORD wtsid_temp = 0xFFFFFFFF;
	PWTS_SESSION_INFO pInfo, pSessInfo = NULL;

	fnProcAddress = GetProcAddress(GetModuleHandle("Kernel32.dll"),
		   	"WTSGetActiveConsoleSessionId");
	memcpy(&fnWTSGetActiveConsoleSessionId,
		   	&fnProcAddress, sizeof(fnProcAddress));

	if (fnWTSGetActiveConsoleSessionId != NULL)
		wtsid_temp = fnWTSGetActiveConsoleSessionId();

	if (wtsid_temp != 0xFFFFFFFF)
		return wtsid_temp;

	if ( WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE,
			   	0, 1, &pSessInfo, &Count) ) {
		for (pInfo = pSessInfo;	pInfo < &pSessInfo[Count]; pInfo++) {
			if (pInfo->State == WTSActive)
				wtsid = pInfo->SessionId;
		}
		WTSFreeMemory(pSessInfo);
	}

	return wtsid;
}

int list_session_identity()
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return -1;

	if ( !Process32First(hSnap, &entry) ) {
		CloseHandle(hSnap);
		return -1;
	}

	do {
		DWORD sessId = 0;
		ProcessIdToSessionId(entry.th32ProcessID, &sessId);
		printf("name %s, \t\tsession id: %d\n", entry.szExeFile, sessId);
	} while ( Process32Next(hSnap, &entry) );

	CloseHandle(hSnap);
	return 0;
}

BOOL CALLBACK EnumWindowStationProc(LPTSTR name, LPARAM lParam)
{
	printf("Station: %s\n", name);
	return TRUE;
}

BOOL CALLBACK EnumDesktopProc(LPTSTR name, LPARAM lParam)
{
	printf("Desktop: %s\\%s\n", lParam, name);
	return TRUE;
}

int list_desktop(const char * name)
{
	HWINSTA hWinSta;
	if (name == NULL) {
		hWinSta = GetProcessWindowStation();
		EnumDesktops(hWinSta, EnumDesktopProc, (LPARAM)".");
		return 0;
	}
	hWinSta = OpenWindowStation(name, FALSE, WINSTA_ENUMDESKTOPS);
	if (hWinSta != NULL) {
		EnumDesktops(hWinSta, EnumDesktopProc, (LPARAM)name);
		CloseWindowStation(hWinSta);
	}
	return 0;
}

int switch_desktop(const char * name)
{
	BOOL bSuccess;
	const char * p = NULL;
	HDESK hDesktop, hInpDesk = NULL;

	p = strchr(name, '\\');
	p = (p == NULL)? strchr(name, '/'): strchr(name, '\\');
	Sleep(10);
	hInpDesk = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
	hDesktop = OpenDesktop((p == NULL)? name: (p + 1),
		   	0, FALSE, DESKTOP_SWITCHDESKTOP);
	abortif(hDesktop == NULL);

	bSuccess = SwitchDesktop(hDesktop);
	printf("SwitchDesktop: %d\n", bSuccess? 0: GetLastError());
	CloseDesktop(hDesktop);

	if (__detach_desktop == 0) {
		Sleep(1000 * __sleep_seconds);
		SwitchDesktop(hInpDesk);
	}
	CloseDesktop(hInpDesk);
	return 0;
}

int new_station(const char * name)
{
	HWINSTA hWinSta = CreateWindowStation(name, 0, GENERIC_ALL, NULL);
	abortif(hWinSta == NULL);
	printf("SetProcessWindowStation %d\n",
			SetProcessWindowStation(hWinSta)? 0: GetLastError());
	HDESK hInpDesk = CreateDesktop("Default", NULL, NULL, 0, GENERIC_ALL, NULL);
	abortif(hInpDesk == NULL);
	printf("station: %s\n", name);
	printf("SetThreadDesktop %d\n",
			SetThreadDesktop(hInpDesk)? 0: GetLastError());
	CloseDesktop(hInpDesk);
	CloseWindowStation(hWinSta);
	return 0;
}

int new_process(const char * name)
{
	STARTUPINFO siInfo = {0};
	PROCESS_INFORMATION piInfo = {0};
	char * module = NULL, * cmdline = (char *)__prog_name;
	printf("new_process: %s\n", __prog_name);
	while (__prog_name != NULL) {
		siInfo.lpDesktop = (char *)name;

		const char * p = NULL;
		abortif(name == NULL);
	   	p = strchr(name, '\\');
	   	p = (p == NULL)? strchr(name, '/'): strchr(name, '\\');
		HDESK hDesk = CreateDesktop(p? (p + 1): name, NULL, NULL, 0, GENERIC_ALL, 0);

		printf("desktop --+<%s>+--, cmdline %s\n", name, cmdline);
		if ( CreateProcess(module, cmdline, NULL, NULL, FALSE,
			NORMAL_PRIORITY_CLASS|CREATE_NO_WINDOW|CREATE_NEW_CONSOLE,
			NULL, NULL, &siInfo, &piInfo) ) {
			CloseHandle(piInfo.hThread);
			CloseHandle(piInfo.hProcess);
		}
		Sleep(100);
		CloseDesktop(hDesk);
		break;
	}

	return 0;
}

void print_helpmsg(const char *prog)
{
	printf("usage %s [option]\n", prog);
	printf("\t --list-pid\n");
	printf("\t --list-station\n");
	printf("\t --list-desktop <station>\n");
	printf("\t --detach-desktop\n");
	printf("\t --switch-desktop <name>\n");
	printf("\t --sleep-seconds <second>\n");
	printf("\t --new-process <desktop>\n");
	printf("\t --prog-name <name>\n");
	printf("\t --new-station <name>\n");
	printf("\t --help\n");
	printf("\n");
}

int desktop_shell(int argc, char* argv[])
{
	for (int i = 0; i < argc; i++) {
		const char * line = argv[i];
		abortif(line == NULL);

		if (strcmp(line, "--list-pid") == 0) {
			list_session_identity();
		} else if (strcmp(line, "--list-station") == 0) {
			EnumWindowStations(EnumWindowStationProc, 0);
		} else if (strcmp(line, "--list-desktop") == 0) {
			list_desktop(i + 1 < argc? argv[i + 1]: NULL);
			i++;
		} else if (strcmp(line, "--list") == 0) {
			list_desktop(i + 1 < argc? argv[i + 1]: NULL);
			i++;
		} else if (strcmp(line, "--detach-desktop") == 0) {
			/* detach desktop */
			__detach_desktop = 1;
		} else if (strcmp(line, "--switch-desktop") == 0) {
			const char * path = (i + 1 < argc? argv[i + 1]: NULL);
			abortif(path == NULL);
			switch_desktop(path);
			i++;
		} else if (strcmp(line, "--sleep-seconds") == 0) {
			__sleep_seconds = atoi(i + 1< argc? argv[i + 1]: "16");
			i++;
		} else if (strcmp(line, "--prog-name") == 0) {
			__prog_name = (i + 1 < argc)? argv[i + 1]: __prog_name;
			i++;
		} else if (strcmp(line, "--new-station") == 0) {
			const char * name = (i + 1 < argc)? argv[i + 1]: NULL;
			abortif(name == NULL);
			new_station(name);
			i++;
		} else if (strcmp(line, "--new-process") == 0) {
			const char * name = (i + 1 < argc)? argv[i + 1]: __prog_name;
			new_process(name);
			i++;
		} else if (strcmp(line, "--help") == 0) {
			print_helpmsg(argv[0]);
			i++;
		}
	}
	Sleep(10);
	return 0;
}

const char * fncpy(char * dst, size_t len, const char * src, const char * ext)
{
	char ign = 0;
	size_t l = len;
	char * s = dst;
	char * lastchar = &ign;

	strncpy(dst, src, len);
	while (l > 0 && *s != 0) {
		if (*s == '/' || 
				*s == '.' ||
				*s == '\\')
			lastchar = s;
		s++;
		l--;
	}

	if (*lastchar == '.')
		*lastchar = '\0';
	strncat(dst, ext, len);
	return dst;
}

int main(int argc, char* argv[])
{
	int i, ch;
	int len;
	int count;
	char cfg_name[1024];
	char mod_name[1024];
	char cfg_buffer[65536];
	FILE * cfg_file = NULL;
	const char * cfg_path = 0;
	char * buf, * p;

	if (argc > 1)
		return desktop_shell(argc - 1, argv + 1);

	len = GetModuleFileName(NULL, mod_name, sizeof(mod_name));
	if (len >= sizeof(mod_name))
		return -1;

	cfg_path = fncpy(cfg_name, sizeof(cfg_name), mod_name, ".cfg");
	cfg_file = fopen(cfg_path, "r");
	if (cfg_file == NULL)
		return -1;

	count = 0;
	buf = cfg_buffer;
	len = sizeof(cfg_buffer);
	while (fgets(buf, len, cfg_file)) {
		int llen = strlen(buf) + 1;
		abortif(len < llen);
		buf += llen;
		len -= llen;
		count++;
	}
	fclose(cfg_file);

	if (count == 0)
		return -1;

	argc = 0;
	argv = (char **) malloc(sizeof(char *) * count);

	argc = ch = 0;
	for (p = cfg_buffer; p < buf; p++) {
		if (ch == 0 && *p && *p != '#')
			argv[argc++] = p;
		ch = *p;
		if (*p == '\r' || *p =='\n')
			*p = 0;
	}

	if (argc == 0)
		return 0;

	if (*argv[0] == '@') {
		freopen(argv[0] + 1, "w", stdout);
		desktop_shell(argc - 1, argv + 1);
		fclose(stdout);
	} else {
		/* just write to console */
		desktop_shell(argc , argv );
	}

	free(argv);
	return 0;
}

