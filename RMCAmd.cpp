#include <stdio.h>
#include <ctype.h>
#include <windows.h>

#define I(str) #str

const char ACPI_DEV_NAME[] = {
	"\\\\.\\RTCore32"
};

int tohex(int ch)
{
	int uch = (ch & 0xFF);
	if (uch >= '0' && uch <= '9')
		return uch - '0';
	if (uch >= 'a' && uch <= 'f')
		return uch - 'a' + 10;
	if (uch >= 'A' && uch <= 'F')
		return uch - 'A' + 10;
	return 0;
}

size_t HexToMemory(const char * hex, void * buf, size_t len)
{
	int code;
	unsigned char * p = (unsigned char *)buf;
	while (len > 0) {
		if (*hex == 0) break;
		code = tohex(*hex++);
		if (*hex == 0) break;
		code = (code << 4) | tohex(*hex++);
		*p++ = (unsigned char)code;
		len--;
	}
	return p - (unsigned char *)buf;
}

static char asm_code[] = {
	0xFA, 0xB9, 0x41, 0x00, 0x01, 0xC0, 0x0F, 0x30,
	0x33, 0xDB, 0xB9, 0x42, 0x00, 0x01, 0xC0, 0x90,
	0x83, 0xC3, 0x01, 0x0F, 0x32, 0x85, 0xC0, 0x78,
	0xF7, 0xFB, 0xC3
};

//I(0x00011100, 0x000007D0, 0x0040700e);

static DWORD ret_bytes = 0;
static char  in_buf[8192], out_buf[8192], line[1024];

char *exec_alloc(void *imgbase, size_t count)
{
    void *pvoid = VirtualAlloc(imgbase, count,
	    MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pvoid == NULL) {
       	pvoid = VirtualAlloc(NULL, count,
	       	MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    return (char*)pvoid;
}

int dummy_call()
{
	return 0;
}

void detect(void)
{
	int i;
	BOOL success;

	HANDLE hACPI = CreateFile(ACPI_DEV_NAME, GENERIC_READ|GENERIC_WRITE,
			FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if 0
	if (hACPI == INVALID_HANDLE_VALUE) return;

	printf("Load RTCore32\n");
	unsigned char in_tag[] = {0x88, 0xA2, 0x57, 0x00, 0xB8, 0x4A, 0x43, 0x00};
	ret_bytes = 8;
   	success = DeviceIoControl(hACPI, 0x80002028, in_tag, 8,
						in_buf, 8, &ret_bytes, NULL);
	for (int k = 0; k < ret_bytes; k++)
		printf("%02x ", in_buf[k] & 0xFF);
	printf("success: %d\n", success);
#endif

	DWORD ctl_argu[7];
	memset(ctl_argu, 0, sizeof(ctl_argu));
	void * palloc = exec_alloc(0, 4096);
	ctl_argu[0] = 0x00011104;
	ctl_argu[3] = 0x000007D0;
	ctl_argu[6] = (DWORD)palloc;
	memcpy(palloc, asm_code, sizeof(asm_code));
   	success = DeviceIoControl(hACPI, 0x80002020, ctl_argu, sizeof(ctl_argu),
		   	ctl_argu, sizeof(ctl_argu), &ret_bytes, NULL);
   	printf(success? "i %d, ret %d\n": "i %d Error\n", 0, ret_bytes);
	for (i = 0; i < 7; i++)
		printf("%02x ", ctl_argu[i]);
	printf("\n");
	CloseHandle(hACPI);
}

int main(int argc, char * argv[])
{
	detect();
	return 0;
}

