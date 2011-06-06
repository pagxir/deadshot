#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <ctype.h>
#include <windows.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

void usage(char *pname)
{
	printf("Usage: %s [options] ip-address\n", pname);
	printf("\t -h \t\thelp\n");
	printf("\t -l length \tMAC physical address length to set\n");
	printf("\t -s src-ip \tsource IP address\n");
	exit(1);
}

int __cdecl main(int argc, char **argv)
{
	DWORD dwRetVal;
	IPAddr DestIp = 0;
	IPAddr SrcIp = 0;       /* default for src ip */
	ULONG MacAddr[2];       /* for 6-byte hardware addresses */
	ULONG PhysAddrLen = 6;  /* default to length of six bytes */

	char *DestIpString = NULL;
	char *SrcIpString = NULL;

	BYTE *bPhysAddr;
	int i;

	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			if ((argv[i][0] == '-') || (argv[i][0] == '/')) {
				switch (tolower(argv[i][1])) {
					case 'l':
						PhysAddrLen = (ULONG) atol(argv[++i]);
						break;
					case 's':
						SrcIpString = argv[++i];
						SrcIp = inet_addr(SrcIpString);
						break;
					case 'h':
					default:
						usage(argv[0]);
						break;
				}               /* end switch */
			} else
				DestIpString = argv[i];
		}                       /* end for */
	} else
		usage(argv[0]);

	if (DestIpString == NULL || DestIpString[0] == '\0')
		usage(argv[0]);

	DestIp = inet_addr(DestIpString);

	memset(&MacAddr, 0xff, sizeof (MacAddr));

	/* printf("Sending ARP request for IP address: %s\n", DestIpString); */

	dwRetVal = SendARP(DestIp, SrcIp, MacAddr, &PhysAddrLen);

	if (dwRetVal == NO_ERROR) {
		bPhysAddr = (BYTE *) & MacAddr;
		if (PhysAddrLen) {
			printf("Sending ARP request for IP address: %s\n", DestIpString); 
			for (i = 0; i < (int) PhysAddrLen; i++) {
				if (i == (PhysAddrLen - 1))
					printf("%.2X\n", (int) bPhysAddr[i]);
				else
					printf("%.2X-", (int) bPhysAddr[i]);
			}
		} else
			printf
				("Warning: SendArp completed successfully, but returned length=0\n");

	} else {
#if 0
		printf("Error: SendArp failed with error: %d", dwRetVal);
		switch (dwRetVal) {
			case ERROR_GEN_FAILURE:
				printf(" (ERROR_GEN_FAILURE)\n");
				break;
			case ERROR_INVALID_PARAMETER:
				printf(" (ERROR_INVALID_PARAMETER)\n");
				break;
			case ERROR_INVALID_USER_BUFFER:
				printf(" (ERROR_INVALID_USER_BUFFER)\n");
				break;
			case ERROR_BAD_NET_NAME:
				printf(" (ERROR_GEN_FAILURE)\n");
				break;
			case ERROR_BUFFER_OVERFLOW:
				printf(" (ERROR_BUFFER_OVERFLOW)\n");
				break;
			case ERROR_NOT_FOUND:
				printf(" (ERROR_NOT_FOUND)\n");
				break;
			default:
				printf("\n");
				break;
		}
#endif
	}

	return 0;
}
