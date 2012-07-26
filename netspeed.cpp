//

#include "stdafx.h"
#include <windows.h>
#include <iphlpapi.h>

int _index = 0;
DWORD _total_in = 0;
DWORD _total_out = 0;
DWORD _ring_in[180];
DWORD _ring_out[180];
DWORD _speedin_10sec = 0;
DWORD _speedout_10sec = 0;
DWORD _speedin_40sec = 0;
DWORD _speedout_40sec = 0;
DWORD _speedin_180sec = 0;
DWORD _speedout_180sec = 0;

int main(int argc, char * argv[])
{
	int index;
	DWORD count;
	DWORD in, out;
	MIB_IFROW stat, stat1;
	
	GetNumberOfInterfaces(&count);

	if (argc == 1) {
		for (int i = 0; i < count; i++) {
			stat.dwIndex = (i + 1);
			GetIfEntry(&stat);
			printf("%d %s\n", (i + 1), stat.bDescr);
		}
	} else do {
		index = atoi(argv[1]);
		if (index <= 0 || index > count)
			break;

		stat1.dwIndex = index;
		GetIfEntry(&stat1);
		stat.dwIndex = index;

		for ( ; ; ) {
			GetIfEntry(&stat);
			in = int(stat.dwInOctets - stat1.dwInOctets);
			out = int(stat.dwOutOctets - stat1.dwOutOctets);

			_speedin_10sec += in;
			_speedin_10sec -= _ring_in[(_index + 180 - 10) % 180];
			_speedout_10sec += out;
			_speedout_10sec -= _ring_out[(_index + 180 - 10) % 180];
			_speedin_40sec += in;
			_speedin_40sec -= _ring_in[(_index + 180 - 40) % 180];
			_speedout_40sec += out;
			_speedout_40sec -= _ring_out[(_index + 180 - 40) % 180];
			_speedin_180sec += in;
			_speedin_180sec -= _ring_in[(_index) % 180];
			_speedout_180sec += out;
			_speedout_180sec -= _ring_out[(_index) % 180];

			_ring_in[_index % 180] = in;
			_ring_out[_index % 180] = out;

			_total_in = (_total_in + in) / 2;
			_total_out = (_total_out/2 + out) / 2;
			_index++;

			fprintf(stderr, "\r%6u/%-5u %6u/%-5u %6u/%-5u %6u/%-5u",
				_total_in, _total_out,
				_speedin_10sec/10, _speedout_10sec/10,
				_speedin_40sec/40, _speedout_40sec/40,
				_speedin_180sec/180, _speedout_180sec/180);

			stat1 = stat;
			Sleep(1000);
		}
	} while ( 0 );

	return 0;
}

