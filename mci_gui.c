#include <stdio.h>
#include <windows.h>
#include <vfw.h>

int main(int argc, char *argv[])
{
	MSG msg;
	HWND hWnd;
	int deviceID, result;

   	hWnd = MCIWndCreate(NULL, NULL,
		   	WS_OVERLAPPED | WS_CAPTION | WS_BORDER | WS_SYSMENU |
		   	WS_VISIBLE | MCIWNDF_RECORD | MCIWNDF_SHOWALL, NULL);

	MCIWndNew(hWnd, "waveaudio");
	MCI_WAVE_SET_PARMS set_parms;
	set_parms.wFormatTag      = WAVE_FORMAT_PCM;
	set_parms.wBitsPerSample  = 16;
	set_parms.nChannels       = 1;
	set_parms.nBlockAlign     = (set_parms.nChannels*set_parms.wBitsPerSample)/8;
	set_parms.nSamplesPerSec  = 44100;
	set_parms.nAvgBytesPerSec = ((set_parms.wBitsPerSample) *
		   	set_parms.nChannels *
			set_parms.nSamplesPerSec) / 8;

	// now send the format changes with MCI_SET
	deviceID = MCIWndGetDeviceID(hWnd);
	result = mciSendCommand(deviceID, MCI_SET,
			MCI_WAIT
			| MCI_WAVE_SET_FORMATTAG
			| MCI_WAVE_SET_BITSPERSAMPLE
			| MCI_WAVE_SET_CHANNELS
			| MCI_WAVE_SET_SAMPLESPERSEC
			| MCI_WAVE_SET_AVGBYTESPERSEC
			| MCI_WAVE_SET_BLOCKALIGN,
			(DWORD)(LPVOID)&set_parms);
	MCIWndRecord(hWnd);  //开始录制

	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	MCIWndStop(hWnd);  //录制完毕
	MCIWndSave(hWnd, L"abc.wav");   //保存
	MCIWndClose(hWnd);
	MCIWndDestroy(hWnd);
	return 0;
}

