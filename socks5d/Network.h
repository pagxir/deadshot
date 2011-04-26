#ifndef _NDSSERVICE_H_
#define _NDSSERVICE_H_

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

typedef void ASYNCCALL(LPVOID context);

#define AF_FINISH  1
#define AF_PENDING 2
#define AF_SUCCESS 4
#define AF_FAILURE 8

typedef struct _AIOCB {
	OVERLAPPED overlapped;
	DWORD magic;
	DWORD state; // do not editing in multithread 
	DWORD count;
	LPVOID context;
	ASYNCCALL * callback;
} AIOCB;

#define AIOCB_ISFINISH(acb)  ((acb)->state & AF_FINISH)
#define AIOCB_ISPENDING(acb) ((acb)->state & AF_PENDING)

#define AIOCB_CLEAR(acb) \
	do { \
	DS_ASSERT(!AIOCB_ISPENDING(acb)); \
	(acb)->state &= ~AF_FINISH; \
	} while ( 0 )

typedef struct _Callout {
	DWORD magic;
	DWORD state; // do not editing in multithread 
	DWORD ttick;
	LPVOID context;
	ASYNCCALL * callback;
	struct _Callout * next;
	struct _Callout * priv;
	struct _Callout * father;
	struct _Callout * child1st;
} Callout;

void CalloutInit(Callout * tcb);
void CalloutStop(Callout * tcb);
void CalloutDrop(Callout * tcb);
void CalloutReset(Callout * tcb, ASYNCCALL * cb, LPVOID ctx, DWORD timo);

BOOL AsyncIoCompletion(AIOCB * acb, DWORD count);
BOOL AssociateDeviceWithCompletionPort(HANDLE hDevice, ULONG_PTR ulCompleteKey);

int AIO_WSARecv(SOCKET s, PVOID buf, size_t len, AIOCB * acb);
int AIO_WSASend(SOCKET s, CONST PVOID buf, size_t len, AIOCB * acb);
int AIO_WSASendTo(SOCKET s, CONST PVOID buf, size_t len, CONST PSOCKADDR pto, int tolen, AIOCB * acb);
int AIO_WSARecvFrom(SOCKET s, PVOID buf, size_t len, PSOCKADDR pfrom, PINT pfromlen, AIOCB * acb);
BOOL PushAsyncCall(AIOCB * acb);
BOOL AIO_DisconnectEx(SOCKET file, AIOCB * acb);
BOOL AIO_AcceptEx(SOCKET sl, SOCKET sa, PVOID buf, DWORD len, DWORD lal, DWORD ral, AIOCB * acb);
BOOL AIO_ConnectEx(SOCKET s, const struct sockaddr * name, int namelen, const PVOID buf, size_t len, AIOCB * acb);
void AIOCB_Init(AIOCB * acb, ASYNCCALL * callback, PVOID context);
void AIOCB_Start(AIOCB * acb);
void AIOCB_Stop(AIOCB * acb);

#endif
