#ifndef _EXCEPTION_H_
#define _EXCEPTION_H_

void SetExceptionDumpHandle(const char * name);
BOOL WriteMiniDumpSnapshot(const char * prefix);
BOOL CreateMiniDump(const char * prefix, struct _EXCEPTION_POINTERS* ExceptionInfo);

#endif
