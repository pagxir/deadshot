#include "Stdafx.h"
#include <time.h>
#include <stdio.h>
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>

#include <set>

#include "SDServer.h"
#include "Network.h"
#include "HeapSort.h"

static LPFN_ACCEPTEX lpfnAcceptEx = NULL;
static LPFN_CONNECTEX lpfnConnectEx = NULL;
static LPFN_DISCONNECTEX lpfnDisconnectEx = NULL;

static void RelocFunction(void)
{
	int fd;
	int error;
	DWORD dwBytes;
	
	fd = socket(AF_INET, SOCK_STREAM, 0);
	DS_ASSERT(fd != -1);

#define XX(guid, fnptr) \
	do { \
	GUID fn_##guid = guid; \
	error = WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, \
	&fn_##guid, sizeof(fn_##guid), &fnptr, sizeof(fnptr), &dwBytes, NULL, NULL); \
	} while ( 0 )

	XX(WSAID_ACCEPTEX, lpfnAcceptEx);
	XX(WSAID_CONNECTEX, lpfnConnectEx);
	XX(WSAID_DISCONNECTEX, lpfnDisconnectEx);
#undef XX

	DS_ASSERT(lpfnConnectEx != NULL);
	DS_ASSERT(lpfnAcceptEx != NULL);

	closesocket(fd);
}

void AIOCB_Init(AIOCB * acb, ASYNCCALL * callback, LPVOID context)
{
	DS_ASSERT(acb != NULL);

	acb->state = 0;
	acb->magic = 0x19821130;
	acb->context = context;
	acb->callback = callback;
}

void AIOCB_Start(AIOCB * acb)
{
	DS_ASSERT(acb != NULL);
	DS_ASSERT(acb->magic == 0x19821130);

	DS_ASSERT((acb->state & AF_PENDING) == 0);
	memset(&acb->overlapped, 0, sizeof(acb->overlapped));
	acb->state |= AF_PENDING;
	acb->state &= ~AF_FINISH;
	acb->state &= ~AF_SUCCESS;
	acb->state &= ~AF_FAILURE;
}

void AIOCB_Stop(AIOCB * acb)
{
	DS_ASSERT(acb != NULL);
	DS_ASSERT(acb->magic == 0x19821130);

	DS_ASSERT(acb->state & AF_PENDING);
	acb->state &= ~AF_PENDING;
}

int AIO_WSARecv(SOCKET s, PVOID buf, size_t len, AIOCB * acb)
{
	int result;
	static DWORD flags = 0;
	static DWORD ignore = 0;
	WSABUF wsabuf[2];

	wsabuf[0].len = len;
	wsabuf[0].buf = (PCHAR) buf;

	AIOCB_Start(acb);
	result = WSARecv(s, wsabuf, 1, &ignore, &flags, &acb->overlapped, 0);

	if (result != 0 && 
		WSAGetLastError() != WSA_IO_PENDING)
		AIOCB_Stop(acb);

	return result;
}

int AIO_WSASend(SOCKET s, CONST PVOID buf, size_t len, AIOCB * acb)
{
	int result;
	static DWORD ignore = 0;
	WSABUF wsabuf[2];

	wsabuf[0].len = len;
	wsabuf[0].buf = (PCHAR)buf;

	AIOCB_Start(acb);
	result = WSASend(s, wsabuf, 1, &ignore, 0, &acb->overlapped, 0);

	if (result != 0 && 
		WSAGetLastError() != WSA_IO_PENDING)
		AIOCB_Stop(acb);

	return result;
}

int AIO_WSASendTo(SOCKET s, CONST PVOID buf, size_t len, CONST PSOCKADDR pto, int tolen, AIOCB * acb)
{
	int result;
	static DWORD ignore = 0;
	WSABUF wsabuf[2];

	wsabuf[0].len = len;
	wsabuf[0].buf = (PCHAR)buf;

	AIOCB_Start(acb);
	result = WSASendTo(s, wsabuf, 1, &ignore, 0, pto, tolen, &acb->overlapped, 0);

	if (result != 0 && 
		WSAGetLastError() != WSA_IO_PENDING)
		AIOCB_Stop(acb);

	return result;
}

int AIO_WSARecvFrom(SOCKET s, PVOID buf, size_t len, PSOCKADDR pfrom, PINT pfromlen, AIOCB * acb)
{
	int result;
	static DWORD flags = 0;
	static DWORD ignore = 0;
	WSABUF wsabuf[2];

	wsabuf[0].len = len;
	wsabuf[0].buf = (PCHAR)buf;

	AIOCB_Start(acb);
	result = WSARecvFrom(s, wsabuf, 1, &ignore, &flags, pfrom, pfromlen, &acb->overlapped, 0);

	if (result != 0 && 
		WSAGetLastError() != WSA_IO_PENDING)
		AIOCB_Stop(acb);

	return result;
}

BOOL AIO_AcceptEx(SOCKET sl, SOCKET sa, PVOID buf, DWORD len, DWORD lal, DWORD ral, AIOCB * acb)
{
	BOOL success;
	static DWORD ignore;

	AIOCB_Start(acb);
	success = lpfnAcceptEx(sl, sa, buf, len, lal, ral, &ignore, &acb->overlapped);

	if (success == FALSE &&
		WSAGetLastError() != WSA_IO_PENDING)
		AIOCB_Stop(acb);

	return success;
}

BOOL AIO_ConnectEx(SOCKET s, const struct sockaddr * name, int namelen, const PVOID buf, size_t len, AIOCB * acb)
{
	BOOL success;
	static DWORD ignore;

	AIOCB_Start(acb);
	success = lpfnConnectEx(s, name, namelen, buf, len, &ignore, &acb->overlapped);

	if (success == FALSE &&
		WSAGetLastError() != WSA_IO_PENDING)
		AIOCB_Stop(acb);

	return success;
}

BOOL AIO_DisconnectEx(SOCKET file, AIOCB * acb)
{	
	BOOL success = FALSE;

	WSASetLastError(WSAEINVAL);

	if (lpfnDisconnectEx != NULL) {
		AIOCB_Start(acb);
		success = lpfnDisconnectEx(file, &acb->overlapped, 0, 0);

		if (success == FALSE &&
			WSAGetLastError() != WSA_IO_PENDING)
			AIOCB_Stop(acb);
	}

	return success;
}

struct callout_less
{
	bool operator() (const Callout * a, const Callout * b) const
	{
		if (a->ttick != b->ttick)
			return int(a->ttick - b->ttick) < 0;

		return (a < b);
	}
};

static std::set<Callout *, callout_less> _timer_callout_set;

void CalloutInit(Callout * tcb)
{
	memset(tcb, 0, sizeof(Callout));
	tcb->magic = 0x19821130;
}

void CalloutStop(Callout * tcb)
{
	DS_ASSERT(tcb->magic == 0x19821130);

	if (tcb->state & AF_PENDING) {
		_timer_callout_set.erase(tcb);
		tcb->state &= ~AF_PENDING;
	}
}

void CalloutDrop(Callout * tcb)
{
	CalloutStop(tcb);
	tcb->magic = 0;
}

void CalloutReset(Callout * tcb, ASYNCCALL * cb, LPVOID ctx, DWORD timo)
{
	DWORD c = GetTickCount();
	DWORD flag = tcb->state;
	DS_ASSERT(tcb->magic == 0x19821130);
	DS_ASSERT(timo < 1000 * 60 * 60 * 24 * 7);

	if (flag & AF_PENDING) {
		_timer_callout_set.erase(tcb);
		tcb->state &= ~AF_PENDING;
	}

	tcb->callback = cb;
	tcb->context = ctx;
	tcb->ttick = (c + timo);
	tcb->state |= AF_PENDING;
	_timer_callout_set.insert(tcb);
}

static DWORD CalloutInvoke(void)
{
	DWORD timo = INFINITE;
	Callout * p = NULL;
	DWORD tick = GetTickCount();
	std::set<Callout *, callout_less>::iterator iter;

	while (!_timer_callout_set.empty()) {
		iter = _timer_callout_set.begin();

		p = *iter;
		if (int(p->ttick - tick) > 0) {
			timo = (p->ttick - tick);
			break;
		}

		_timer_callout_set.erase(iter);

		if (p->state & AF_PENDING) {
			p->state &= ~AF_PENDING;
			p->callback(p->context);
		}
	}

	if (timo < 200) {
		timo = 200;
	}

	return timo;
}

typedef struct _PluginParam {
	HANDLE hThread;
	BOOL   bQuited;
	HANDLE hIoCompletionPort;
} PluginParam, * PPluginParam;

static PluginParam Network;
static DWORD CALLBACK NetworkThread(LPVOID lpVoid);

static int NetworkStart(void)
{
	DWORD ThreadId;
	Network.bQuited = FALSE;
	Network.hThread = CreateThread(NULL, 0, NetworkThread, &Network, 0, &ThreadId);
	DS_ASSERT(Network.hThread != NULL);
	return 0;
}

static int NetworkStop(void)
{
	Network.bQuited = TRUE;
	PostQueuedCompletionStatus(Network.hIoCompletionPort, 0, NULL, NULL);
	WaitForSingleObject(Network.hThread, INFINITE);
	CloseHandle(Network.hThread);
	return 0;
}

static int NetworkInit(void)
{
	HANDLE hPort;
	WSADATA wsadata;
	int error = WSAStartup(0x101, &wsadata);

	Network.hIoCompletionPort = hPort 
		= CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	NASSERT(hPort != NULL);

	RelocFunction();
	return 0;
}

static int NetworkClean(void)
{
	CloseHandle(Network.hIoCompletionPort);
	WSACleanup();
	return 0;
}

BOOL PushAsyncCall(AIOCB * acb)
{
	BOOL success;

	if (Network.bQuited)
		return FALSE;

	AIOCB_Start(acb);	
	success = PostQueuedCompletionStatus(Network.hIoCompletionPort,
		0, (ULONG_PTR)&Network, &acb->overlapped);

	if (success == FALSE)
		AIOCB_Stop(acb);

	return success;
}


BOOL AsyncIoCompletion(AIOCB * acb, DWORD count)
{
	BOOL success = FALSE;
	HANDLE hPort = Network.hIoCompletionPort;

	if (Network.bQuited)
		return FALSE;

	DS_ASSERT(acb->magic == 0x19821130);
	DS_ASSERT(acb->state & AF_PENDING);
	success = PostQueuedCompletionStatus(hPort, count, (ULONG_PTR)&Network, &acb->overlapped);

	return success;
}

static DWORD CALLBACK NetworkThread(LPVOID lpVoid)
{
	BOOL status;
	DWORD timo;
	DWORD iosize;
	HANDLE hPort;
	ULONG_PTR key;
	LPOVERLAPPED io_data;
	AIOCB * cbAsync;
	
	PPluginParam lParam = (PPluginParam)lpVoid;
	hPort = lParam->hIoCompletionPort;
	
	while (lParam->bQuited == FALSE) {

		io_data = NULL;
		timo = CalloutInvoke();
		status = GetQueuedCompletionStatus(hPort, &iosize, &key, &io_data, timo);

		if (io_data == NULL) {
			if (status == FALSE) {
				continue;
			}

			break;
		}

		cbAsync = (AIOCB *)io_data;

		DS_ASSERT(key == (ULONG_PTR)lpVoid);
		DS_ASSERT(cbAsync->callback != NULL);
		DS_ASSERT(cbAsync->magic = 0x19821130);
		DS_ASSERT(cbAsync->state & AF_PENDING);

		cbAsync->count = iosize;
		cbAsync->state |= AF_FINISH;
		cbAsync->state &= ~AF_PENDING;
		cbAsync->state |= (status? AF_SUCCESS: AF_FAILURE);
		cbAsync->callback(cbAsync->context);
	}

	return 0;
}

BOOL AssociateDeviceWithCompletionPort(HANDLE hDevice, ULONG_PTR ulCompleteKey)
{
	HANDLE handle;

	ulCompleteKey = (ULONG_PTR)&Network;
	handle = CreateIoCompletionPort(hDevice, Network.hIoCompletionPort, ulCompleteKey, 0);

	return (handle == Network.hIoCompletionPort);
}

DSPLUGIN_EXPORT int DSGetPlugin_Network(PDSClientPlugin pplugin)
{
	pplugin->initialize = NetworkInit;
	pplugin->clean = NetworkClean;

	pplugin->start = NetworkStart;
	pplugin->stop = NetworkStop;
	return 0;
}
