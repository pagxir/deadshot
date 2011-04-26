#ifndef __UTILS_H__
#define __UTILS_H__

/* Warning: MAXSOBUFSZ should less than 64 * 1024.
 * Otherwise will break on some windows 2000 os which will return WSAENOBUF error.
 */

#define MAXSOBUFSZ (16 * 1024)
#define SOBUFADJ(len) ((len) < (MAXSOBUFSZ)? (len): (MAXSOBUFSZ))

int UTF8CharToOEMChar(char *dst, const char *src, size_t len);
int OEMCharToUTF8Char(char *dst, const char *src, size_t len);

BOOL GetFormatedFullPathName(const char *path, char *buf, size_t len);
BOOL GetPathAttribute(const char *path, LPWIN32_FIND_DATA lpFindData);
int GetRelativeFullPath(const char *base, const char *name, char *buf, size_t len);
int SearchFilePath(const char *path, char *buf, size_t bufsz);
int FormatPathSlash(char *path);
inline int IsPathSlash(int slash) { return slash == '/' || slash == '\\'; };

int strlcat(char *dst, const char *src, size_t len);
int strlcpy(char *dst, const char *src, size_t len);

const char *GetPathBaseName(const char *path);

int ds_abort(const char * msg, const char * exp, const char * file, int line);
#define RT_ASSERT(exp, msg) ((exp) || ds_abort(msg, #exp, __FILE__, __LINE__))

typedef struct sqlite3 sqlite3;
extern "C" int sqlite3_open(const char * path, sqlite3 ** dbase);

static int sqlite3_open_ansi(const char * path, sqlite3 ** dbase)
{
	char buf[4096];
	OEMCharToUTF8Char(buf, path, sizeof(buf));
	return sqlite3_open(buf, dbase);
}

#endif
