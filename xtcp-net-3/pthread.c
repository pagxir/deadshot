#include <winsock2.h>
#include <windows.h>

#include "pthread.h"

int pipe(int fildes[2])
{
	int tcp;
	int namelen;
	int tcp1, tcp2;
	struct sockaddr_in name;
	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	namelen = sizeof(name);
	tcp1 = tcp2 = -1;

	tcp = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp == -1) {
		goto clean;
	}
	if (bind(tcp, (struct sockaddr*)&name, namelen) == -1) {
		goto clean;
	}
	if (listen(tcp, 5) == -1) {
		goto clean;
	}
	if (getsockname(tcp, (struct sockaddr*)&name, &namelen) == -1) {
		goto clean;
	}
	tcp1 = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp1 == -1) {
		goto clean;
	}
	if (-1 == connect(tcp1, (struct sockaddr*)&name, namelen)) {
		goto clean;
	}

	tcp2 = accept(tcp, (struct sockaddr*)&name, &namelen);
	if (tcp2 == -1) {
		goto clean;
	}
	if (closesocket(tcp) == -1) {
		goto clean;
	}
	fildes[0] = tcp1;
	fildes[1] = tcp2;
	return 0;
clean:
	if (tcp != -1) {
		closesocket(tcp);
	}
	if (tcp2 != -1) {
		closesocket(tcp2);
	}
	if (tcp1 != -1) {
		closesocket(tcp1);
	}
	return -1;
}

static DWORD CALLBACK PTHREAD_WRAPPER(LPVOID Parameter)
{
	pthread_t * thread = (pthread_t *)Parameter;
	thread->value_ptr = thread->routine(thread->arg);
	return 0;
}

int pthread_create(pthread_t * thread, const pthread_attr_t * attr,
		void * (* routine)(void *), void * arg)
{
	HANDLE handle = NULL;
	thread->arg = arg;
	thread->routine = routine;
	handle = CreateThread(NULL, 0, PTHREAD_WRAPPER, thread, 0, &thread->tid);
	thread->handle = handle;
	return 0;
}

int pthread_join(pthread_t tid, void ** value_ptr)
{
	WaitForSingleObject(tid.handle, INFINITE);
	CloseHandle(tid.handle);
	*value_ptr = tid.value_ptr;
	return 0;
}

