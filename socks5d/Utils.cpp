#include <io.h>
#include <time.h>
#include <stdio.h>
#include <windows.h>
#include <assert.h>
#include <ctype.h>
#include <psapi.h>

#include "Utils.h"

int UTF8CharToOEMChar(char *dst, const char *src, size_t len)
{
	int count;
	RT_ASSERT (dst != NULL && len > 0, "UTF8CharToOEMChar: invalid parameter");

	dst[0] = 0;
	WCHAR * wpath = new WCHAR[len];
	MultiByteToWideChar(CP_UTF8, 0, src, -1, wpath, len);
	wpath[len - 1] = 0;
	count = WideCharToMultiByte(CP_OEMCP, 0, wpath, -1, dst, len, NULL, FALSE);
	dst[len - 1] = 0;
	delete[] wpath;
	return count;
}

int OEMCharToUTF8Char(char *dst, const char *src, size_t len)
{
	int count;
	RT_ASSERT(dst != NULL || len > 0, "OEMCharToUTF8Char: invalid parameter");

	dst[0] = 0;
	WCHAR * wpath = new WCHAR[len];
	MultiByteToWideChar(CP_OEMCP, 0, src, -1, wpath, len);
	wpath[len - 1] = 0;
	count = WideCharToMultiByte(CP_UTF8, 0, wpath, -1, dst, len, NULL, FALSE);
	dst[len - 1] = 0;
	delete[] wpath;
	return count;
}

int strlcpy(char *dst, const char *src, size_t len)
{
	char *d = dst;
	const char *s = src;
	size_t n = len;
	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}
	
	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (len != 0)
			*d = '\0';              /* NUL-terminate dst */
		while (*s++)
			;
	}
	
	return(s - src - 1);    /* count does not include NUL */
}

int strlcat(char *dst, const char *src, size_t len)
{
	char *d = dst;
	const char *s = src;
	size_t n = len;
	size_t dlen;
	
	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = len - dlen;

	if (n == 0)
		return(dlen + strlen(s));

	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src)); 
}

int GetRelativeFullPath(const char *base, const char *name, char *buf, size_t len)
{
	int last;

	RT_ASSERT (name != buf, "GetRelativeFullPath: invalid parameter");
	RT_ASSERT (base && name && buf && len, "GetRelativeFullPath: invalid parameter");

	if (*base == 0 || *name == 0)
		return strlcpy(buf, (*name? name: base), len);

	if (isalpha(name[0]) && name[1] == ':' && IsPathSlash(name[2]))
		return strlcpy(buf, name, len);

	last = strlen(base) - 1;
	strlcpy(buf, base, len);
	if (!IsPathSlash(base[last]) &&	!IsPathSlash(*name))
		strlcat(buf, "\\", len);

	if (IsPathSlash(base[last]) &&	IsPathSlash(*name))
		++name;

	return strlcat(buf, name, len);
}

int FormatPathSlash(char *path)
{
	char *src, *dst;
	assert (path != NULL);

	src = dst = path;
	while ( *src ) {
		if (*src == '/')
			*src = '\\';
		if (src != dst)
			*dst = *src;

		/* remove dup path slash */
		if (dst > path && IsPathSlash(*dst) &&
			IsPathSlash(* (dst - 1)))
			dst--;
		dst++;
		src++;
	}

	*dst++ = 0;

	return (dst - path - 1);
}

const char *GetPathBaseName(const char *path)
{
	const char *s = path;
	const char *pSlash = path;

	RT_ASSERT (path != NULL, "GetPathBaseName: invalid parameter");
	while ( *s ) {
		if (IsPathSlash(*s) && *(s + 1) != 0 &&
			!IsPathSlash( *(s + 1) ))
			pSlash = (s + 1);
		s++;
	}

	return pSlash;
}

int SearchFilePath(const char *path, char *buf, size_t bufsz)
{
	size_t len;
	char *part = 0;
	assert (path != buf);
	WIN32_FIND_DATA FindData;

	len = GetFullPathName(path, bufsz, buf, &part);
	if ((0 == len) || (len >= bufsz))
		return 0;


	if (GetPathAttribute(buf, &FindData) &&
		(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
		return len;
	
	len = GetModuleFileName(0, buf, bufsz);
	if ((0 == len) || (len >= bufsz))
		return 0;

	part = strrchr(buf, '\\');
	RT_ASSERT (part != NULL, "SearchFilePath: invalid parameter");
	*(part + 1) = 0;
	len = GetRelativeFullPath(buf, path, buf, bufsz);
	if ((0 == len) || (len >= bufsz))
		return 0;

	if (GetPathAttribute(buf, &FindData) &&
		(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
		return len;

	return 0;
}

BOOL GetPathAttribute(const char *path, LPWIN32_FIND_DATA lpFindData)
{
	HANDLE hFind = FindFirstFile(path, lpFindData);

    if (hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);

	/* Follow is hack for root directory. */
	if (isalpha(path[0]) && path[1]==':' &&
		path[2 + IsPathSlash(path[2])] == 0 &&
		hFind == INVALID_HANDLE_VALUE)
	{
		lpFindData->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
		return TRUE;		
	}

	return (hFind != INVALID_HANDLE_VALUE);
}

BOOL GetFormatedFullPathName(const char *path, char *buf, size_t len)
{
	size_t test;
	char * part;
	
	test = GetFullPathName(path, len, buf, &part);
	if (test > 0 && test < len && IsPathSlash(buf[test - 1]))
		buf[--test] = 0;

	if (test >= len || test == 0)
		return FALSE;

	return TRUE;
}

typedef BOOL (WINAPI * LPFN_GETPROCESSMEMORYINFO)(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);

static BOOL XP_GetProcessMemoryInfo(HANDLE Process,
							 PPROCESS_MEMORY_COUNTERS ppsmemCounters, DWORD cb)
{
	BOOL success;
	HMODULE hModule;
	LPFN_GETPROCESSMEMORYINFO pGetProcessMemoryInfo;

	success = FALSE;
	const char * librarys[] = {"Kernel32.dll", "Psapi.dll"};

	for (int i = 0; librarys[i]; i++) {
		hModule = LoadLibrary(librarys[i]);
		if (hModule == NULL)
			continue;

		pGetProcessMemoryInfo = (LPFN_GETPROCESSMEMORYINFO)GetProcAddress(hModule, "GetProcessMemoryInfo");

		if (pGetProcessMemoryInfo == NULL) {
			FreeLibrary(hModule);
			continue;
		}

		success = pGetProcessMemoryInfo(Process, ppsmemCounters, cb);

		if (hModule != NULL)
			FreeLibrary(hModule);

		break;
	}

	return success;
}

int ds_abort(const char * msg, const char * exp, const char * file, int line)
{
	int len;
	char buf[2048];
	char * pslash = NULL;
	PROCESS_MEMORY_COUNTERS pmc;

	DWORD error = GetLastError();
	DWORD wsa_error = WSAGetLastError();
	
	len = GetModuleFileName(NULL, buf, sizeof(buf));
	if (len > 0 && len < sizeof(buf)) {
		FILE * exception;
		pslash = strstr(buf, ".exe");
		if (pslash && !pslash[4]) {
			*pslash = 0;
		}
		strncat(buf, ".exception", sizeof(buf));
		
		exception = fopen(buf, "a");

		if (exception != NULL) {
			pmc.cb = sizeof(pmc);
			XP_GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
			fprintf(exception, "msg: %s\n", msg);
			fprintf(exception, "exp: %s\n", exp);
			fprintf(exception, "time: %ld\n", time(NULL));
			fprintf(exception, "error: %d, [%d]\n", error, wsa_error);
			fprintf(exception, "file %s, line %d\n", file, line);

#define XX(f) fprintf(exception, "%s: %uK %u\n", #f, pmc.f / 1024, pmc.f);
			XX(PageFaultCount);
			XX(WorkingSetSize);
			XX(QuotaPagedPoolUsage);
			XX(QuotaNonPagedPoolUsage);
			XX(PagefileUsage);
			XX(PeakWorkingSetSize);
			XX(QuotaPeakPagedPoolUsage);
			XX(QuotaPeakNonPagedPoolUsage);
			XX(PeakPagefileUsage);
#undef XX
			fclose(exception);
		}
	}

	RaiseException(EXCEPTION_BREAKPOINT, 0, 0, 0);
	abort();
	return 0;
}