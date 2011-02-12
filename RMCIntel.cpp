#include <stdio.h>
#include <ctype.h>
#include <windows.h>

#define RTCORE32_DEV_NAME "\\\\.\\RTCore32"

static int HexCode(int ch)
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

static size_t HexRead(const char * hex, void * buf, size_t len)
{
	int code;

	unsigned char * p = (unsigned char *)buf;

	unsigned char * orig_buf = p;
	while (len > 0) {
		if (*hex == 0) break;
		code = HexCode(*hex++);
		if (*hex == 0) break;
		code = (code << 4) | HexCode(*hex++);
		*p++ = (unsigned char)code;
		len--;
	}

	return (p - orig_buf);
}

static int cpu_freq(HANDLE dev_rtcore, DWORD code, DWORD v0, DWORD v1, DWORD v2)
{
	BOOL Success;
	DWORD cpu_argu[3], ret_bytes = 0, last_error;
	memset(cpu_argu, 0, sizeof(cpu_argu));

	cpu_argu[0] = v0;
	cpu_argu[1] = v1;
	cpu_argu[2] = v2;

	printf("Control: %8x\n", code);
	printf("Input(12): \t");
	for (int i = 0; i < 3; i++)
		printf("%08x ", cpu_argu[i]);
	printf("\n");

   	Success = DeviceIoControl(dev_rtcore, code, cpu_argu, sizeof(cpu_argu),
		   	cpu_argu, sizeof(cpu_argu), &ret_bytes, NULL);

	if (Success == FALSE) {
	   	last_error = GetLastError();
	   	printf("Error %d\n", last_error);
		return last_error;
	}

	printf("Return(%d): \t", ret_bytes);
	for (int i = 0; i < 3; i++)
		printf("%08x ", cpu_argu[i]);
	printf("\n");

	return 0;
}

static int cpu_control(int argc, char * argv[])
{
	int i;
	BOOL Success;

	HANDLE dev_rtcore = CreateFile(RTCORE32_DEV_NAME,
		   	GENERIC_READ|GENERIC_WRITE,
			FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (dev_rtcore == INVALID_HANDLE_VALUE) return -1;

	printf("Load RTCore32\n");
#if 0
	DWORD ver_argu[2], ret_bytes = 0;
	ver_argu[0] = 0x0057A288;
	ver_argu[1] = 0x00434AB8;
   	Success = DeviceIoControl(dev_rtcore, 0x80002028,
		   	ver_argu, sizeof(ver_argu), ver_argu,
		   	sizeof(ver_argu), &ret_bytes, NULL);

	if (Success != FALSE)
	   	printf("RTCore Version: %08x %08x\n", ver_argu[0], ver_argu[1]);
#endif

	for (i = 1; i < argc; i+=2) {
		DWORD ctl_code;
		DWORD len, argu[3];
		sscanf(argv[i], "%x", &ctl_code);
		len = HexRead(argv[i + 1], argu, sizeof(argu));
		cpu_freq(dev_rtcore, ctl_code, argu[0], argu[1], argu[2]);
	}
#if 0
	/* 1200 MHz 1.125 V */
	cpu_freq(dev_rtcore, 0x011104, 0, 0, 0x07D0, 0, 0);
#endif

	CloseHandle(dev_rtcore);
	return 0;
}

int main(int argc, char * argv[])
{
	cpu_control(argc, argv);
	printf("80002034 99010000000000001E080000\n");
	return 0;
}

