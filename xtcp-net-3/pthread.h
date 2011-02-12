#ifndef _PTHREAD_H_
#define _PTHREAD_H_

#include <windows.h>

typedef struct {
	HANDLE handle;
	DWORD  tid;
	void * arg;
	void * value_ptr;
	void * (* routine)(void *);
} pthread_t;

typedef HANDLE pthread_cond_t;
typedef void * pthread_attr_t;
typedef CRITICAL_SECTION pthread_mutex_t;

#define pthread_mutex_init(lck, attr) InitializeCriticalSection(lck)
#define pthread_mutex_lock(lck)       EnterCriticalSection(lck)
#define pthread_mutex_unlock(lck)     LeaveCriticalSection(lck)
#define pthread_mutex_destroy(lck)    DeleteCriticalSection(lck)

#define pthread_cond_init(cond, attr) \
	*cond = CreateEvent(NULL, FALSE, FALSE, NULL)

#define pthread_cond_signal(cond) SetEvent(*cond)
#define pthread_cond_wait(cond, lck) \
	do { \
		pthread_mutex_unlock(lck); \
		WaitForSingleObject(*cond, INFINITE); \
		pthread_mutex_lock(lck); \
	} while (0)

#define pthread_cond_destroy(cond) CloseHandle(*cond)

int pthread_create(pthread_t * thread, const pthread_attr_t * attr,
		void * (* routine)(void *), void * arg);
int pthread_join(pthread_t tid, void ** value_ptr);

#endif

