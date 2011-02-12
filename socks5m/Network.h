#ifndef _NDSSERVICE_H_
#define _NDSSERVICE_H_
int NDSQuitCall(void);
int NDSMainCall(BOOL IsInterActive);

#define NASSERT(cond) __rt_assert((cond), #cond, __FILE__, __LINE__)
inline void __rt_assert(int cond, const char * msg, const char * file, int line)
{
	if ( !cond ) {
		printf("%s %s %d", msg, file, line);
		int flag = EXCEPTION_ACCESS_VIOLATION;
		RaiseException(flag, 0, 0, NULL);
		Sleep(160 * 1000);
		exit(0);
	}
}

#define  NDSMAGIC 0x19821131

#endif
