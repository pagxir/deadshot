#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#ifdef __WIN32__
#include <windows.h>
#define INIT_TICK()
#else
#include <sys/time.h>
#include <pthread.h>
typedef unsigned int DWORD;
typedef void * LPVOID;
#define CALLBACK
typedef pthread_t HANDLE;
#define WaitForSingleObject(a, b) 

static timeval __startup;
void INIT_TICK()
{
	gettimeofday(&__startup, NULL);
}

HANDLE CreateThread(void * a, int b, DWORD (*c)(void *), void * d, int e, void *f)
{
	pthread_t tid;
	void * (*k)(void*);
	memcpy(&k, &c, sizeof(c));
	pthread_create(&tid, NULL, k, d);
	return tid;
}

int GetTickCount()
{
	struct timeval timeval0;
	gettimeofday(&timeval0, NULL);
	timeval0.tv_sec -= __startup.tv_sec;
	timeval0.tv_usec -= __startup.tv_usec;
	return timeval0.tv_sec * 1000 + timeval0.tv_usec / 1000;
}

#define CloseHandle(h) pthread_join(h, NULL)
#define INFINITE -1
#endif

#define X(shift) (1 << (shift))
static int test_mask[32] = {
	X(0x00), X(0x01), X(0x02), X(0x03), X(0x04), X(0x05), X(0x06), X(0x07),
	X(0x08), X(0x09), X(0x0a), X(0x0b), X(0x0c), X(0x0d), X(0x0e), X(0x0f),
	X(0x10), X(0x11), X(0x12), X(0x13), X(0x14), X(0x15), X(0x16), X(0x17),
	X(0x18), X(0x19), X(0x1a), X(0x1b), X(0x1c), X(0x1d), X(0x1e), X(0x1f),
};

struct lzwc_ctx {
	size_t lc_bpp;
	size_t lc_bitcnt;
	size_t lc_dicode;
	unsigned char lc_testbl[4096 * 256 / 8];
	size_t lc_dictbl[4096 * 256];

	size_t lc_outcnt;
	char lc_outbuff[8192 + 4];

	size_t lc_outbit_cnt;
	uint32_t lc_outbit_buff;
};

inline void lzwc_restart(struct lzwc_ctx * ctxp)
{
	ctxp->lc_dicode = (1 << ctxp->lc_bpp) + 2;
	ctxp->lc_bitcnt = (ctxp->lc_bpp + 1);
	if (ctxp->lc_dicode >= (1 << ctxp->lc_bitcnt))
		ctxp->lc_bitcnt++;
	memset(ctxp->lc_testbl, 0x0, sizeof(ctxp->lc_testbl));
}

inline void lzwc_init(struct lzwc_ctx * ctxp, int bpp)
{
	memset(ctxp, 0, sizeof(struct lzwc_ctx));
	ctxp->lc_bpp = bpp;
	lzwc_restart(ctxp);
}

inline int lzwc_find(struct lzwc_ctx * ctxp, int prefix, int code)
{
	int key = (prefix << 8) | code;
	assert (code < (1 << ctxp->lc_bpp));
	if (ctxp->lc_testbl[key >> 3] &
			test_mask[key & 0x7])
		return ctxp->lc_dictbl[key];
	return -1;
}

inline int lzwc_update(struct lzwc_ctx * ctxp, int prefix, int code)
{
	int key = (prefix << 8) | code;
	ctxp->lc_testbl[key >> 3] |= test_mask[key & 0x7];
	ctxp->lc_dictbl[key] = ctxp->lc_dicode++;
	return ctxp->lc_dicode;
}

void lzwc_output(struct lzwc_ctx * ctxp, size_t code, FILE *fp)
{
	size_t mask = (1 << ctxp->lc_bitcnt) - 1;

	ctxp->lc_outbit_buff |= ((code & mask) << ctxp->lc_outbit_cnt);
	ctxp->lc_outbit_cnt += ctxp->lc_bitcnt;

	while (ctxp->lc_outbit_cnt >= 8) {
		char outch = (ctxp->lc_outbit_buff & 0xFF);
		ctxp->lc_outbuff[ctxp->lc_outcnt++] = outch;
		ctxp->lc_outbit_buff >>= 8;
		ctxp->lc_outbit_cnt -= 8;
	}
	if (ctxp->lc_outcnt >= 8192) {
		if (fp != NULL)
			fwrite(ctxp->lc_outbuff, 1, ctxp->lc_outcnt, fp);
		ctxp->lc_outcnt = 0;
	}
	if (mask < ctxp->lc_dicode) {
		++ctxp->lc_bitcnt;
	}
}

void lzwc_clear(struct lzwc_ctx * ctxp, FILE * fp)
{
	int clear = (1 << ctxp->lc_bpp);
	lzwc_output(ctxp, clear, fp);
}

void lzwc_finish(struct lzwc_ctx * ctxp, size_t code, FILE *fp)
{
	int fin_code = (1 << ctxp->lc_bpp) + 1;
	lzwc_output(ctxp, code, fp);
	lzwc_output(ctxp, fin_code, fp);
	lzwc_output(ctxp, 0, fp);
	if (fp != NULL)
		fwrite(ctxp->lc_outbuff, 1, ctxp->lc_outcnt, fp);
	ctxp->lc_outcnt = 0;
}

static int DATASIZE = (1024 * 1024 * 6);

void rndset(int seed, void * mem, size_t len)
{
	if (len < sizeof(seed)) {
		memcpy(mem, &seed, len);
		return;
	}

	int l = 1;
	int test = 2;
	int * s = (int *)mem;
	while (len > sizeof(seed)) {
		len -= sizeof(seed);
		*s++ = seed;
		if (l > test) {
			test <<= 1;
			seed++;
		}
		l++;
	}
   	memcpy(s, &seed, len);
}

void zip(const void * data, size_t len)
{
	FILE * fout = NULL;
	int prefix = -1;
	int i, j, count;

	struct lzwc_ctx * ctxp = NULL;
	ctxp = (struct lzwc_ctx *) malloc( sizeof(struct lzwc_ctx) );
	assert (ctxp != NULL);
	lzwc_init(ctxp, 8);

	lzwc_clear(ctxp, fout);

	const uint8_t * s = (const uint8_t *)data;
	while (len > 0) {
		len --;
		int code = *s++;
		if (prefix == -1) {
			prefix = code;
			continue;
		}
		int prefix1 = lzwc_find(ctxp, prefix, code);
		if (prefix1 != -1) {
			if (prefix1 > ctxp->lc_dicode)
			printf("%d %d\n", prefix1, ctxp->lc_dicode);
			assert(prefix1 <= ctxp->lc_dicode);
			prefix = prefix1;
			continue;
		}
		lzwc_output(ctxp, prefix, fout);
		if (lzwc_update(ctxp, prefix, code) < 4096) {
			prefix = code;
			continue;
		}
		lzwc_clear(ctxp, fout);
		prefix = code;
		lzwc_restart(ctxp);
	}
	lzwc_finish(ctxp, prefix, fout);
	free(ctxp);
	return;
}

DWORD CALLBACK lzw_by_thread(LPVOID data)
{
	int th1, th2;
	th1 = GetTickCount();
	zip(data, DATASIZE);
	th2 = GetTickCount();
	printf("th1 %d, th2 %d, th2 - th1 = %fs\n",
		   	th1, th2, (th2 - th1) / 1000.0);
	return 0;
}

int thlzw(int thread, int repeat)
{
	int newsize = 0;
	DWORD tid = 0;
	char * data1 = NULL;
	char * data2 = NULL;
	char * data3 = NULL;
	HANDLE hthread[10];
	DWORD t1, t2, t3, tz, th1, th2;

	data1 = (char * ) malloc(DATASIZE);
	data2 = (char * ) malloc(DATASIZE);
	data3 = (char * ) malloc(DATASIZE);
	assert(data1 && data2 && data3);

	int rdx = rand();
	if (rdx < 0x1FFFF)
		rdx = (rdx << 16)|rand();
	printf("rdx: %x\n", rdx);

	rndset(rdx, data1, DATASIZE);
	rndset(rdx, data2, DATASIZE);
	rndset(rdx, data3, DATASIZE);

	thread = (thread & 0xFF) < 10? (thread & 0xFF): 10;
	for (int i = 0; i < repeat; i++) {
		t1 = GetTickCount();
		for (int j = 0; j < thread; j++)
		   	hthread[j] = CreateThread(NULL, 0, lzw_by_thread, data1, 0, &tid);
		th1 = GetTickCount();
		zip(data2, DATASIZE);
		th2 = GetTickCount();
		for (int j = 0; j < thread; j++) {
		   	WaitForSingleObject(hthread[j], INFINITE);
		   	CloseHandle(hthread[j]);
		}
		t2 = GetTickCount();
		zip(data3, DATASIZE);
		t3 = GetTickCount();
	   	printf("th1 %d, th2 %d, th2 - th1 = %fs\n",
			   	th1, th2, (th2 - th1) / 1000.0);
		printf("Multi Thread %fs, Single Thread %fs\n",
			   	(t2 - t1) / 1000.0, (thread + 1) * (t3 - t2) / 1000.0);
	}
	free(data1);
	free(data2);
	free(data3);
	return 0;
}

static int _fn = 4;

static int f(int n)
{
	if (n < 1) return 0;
	if (n < 2) return 1;
	return f(n - 1) + f(n - 2);
}

DWORD CALLBACK acc_by_thread(LPVOID data)
{
	int th1, th2, result;
	th1 = GetTickCount();
	result = f(_fn);
	th2 = GetTickCount();
	printf("th1 %d, th2 %d, th2 - th1 = %fs\n",
		   	th1, th2, (th2 - th1) / 1000.0);
	if (data != NULL)
		memcpy(data, &result, sizeof(result));
	return 0;
}

int thf(int thread, int repeat)
{
	int val;
	DWORD tid;
	HANDLE hthread[10];
	int t1, t2, t3, th1, th2;
	int sr = 0, mr = 0, tr = 0;
	thread = (thread & 0xFF) < 10? (thread & 0xFF): 10;
	for (int i = 0; i < repeat; i++) {
		t1 = GetTickCount();
		for (int j = 0; j < thread; j++)
		   	hthread[j] = CreateThread(NULL, 0, acc_by_thread, &tr, 0, &tid);
		th1 = GetTickCount();
		mr = f(_fn);
		th2 = GetTickCount();
		for (int j = 0; j < thread; j++) {
		   	WaitForSingleObject(hthread[j], INFINITE);
		   	CloseHandle(hthread[j]);
		}
		t2 = GetTickCount();
		sr = f(_fn);
		t3 = GetTickCount();
	   	printf("th1 %d, th2 %d, th2 - th1 = %fs\n",
			   	th1, th2, (th2 - th1) / 1000.0);
		printf("Multi Thread %fs, Single Thread %fs\n",
			   	(t2 - t1) / 1000.0, (thread + 1) * (t3 - t2) / 1000.0);
	}
	return 0;
}

#define AF_LZW 0x0001
#define AF_FOR 0x0002

int main(int argc, char * argv[])
{
	int flags = 0;
	int repeat_count = 1;
	int thread_count = 1;

	INIT_TICK();
	for (int i = 1; i < argc; i++) {
		const char * p = argv[i];
		if (*p != '-')
			continue;
		switch(p[1]) {
			case 't':
			case 'T':
				if (p[2] != 0)
				   	thread_count = atoi(p + 2);
				else if (i + 1 < argc)
					thread_count = atoi(argv[++i]);
				break;
			case 'f':
			case 'F':
				if (p[2] != 0)
				   	_fn = atoi(p + 2);
				else if (i + 1 < argc)
					_fn = atoi(argv[++i]);
				flags |= AF_FOR;
				break;
			case 'z':
			case 'Z':
				if (p[2] != 0)
					p = (p + 2);
				else if (i + 1 < argc)
					p = argv[++i];
				else
					p = "10000000";
			   	DATASIZE = atoi(p);
				if (*p != 0) {
					switch(p[strlen(p) - 1])
					{
						case 'm':
						case 'M':
							DATASIZE *= 1024;
						case 'k':
						case 'K':
							DATASIZE *= 1024;
							break;
						default:
							break;
					}
				}
				flags |= AF_LZW;
				break;
			default:
				if (isdigit(p[1]))
					repeat_count = atoi(p + 1);
				break;
		}
	}

	if (flags == 0)
		flags = AF_LZW;

	if (flags & AF_LZW)
		thlzw(thread_count, repeat_count);

	if (flags & AF_FOR)
		thf(thread_count, repeat_count);

	printf("Data Size: %d\n", DATASIZE);
	return 0;
}