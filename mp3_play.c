#include <stdio.h>
#include <assert.h>
#include <windows.h>
#include <mmsystem.h>
#include "mpg123.h"

static HANDLE _ghEvent = NULL;
static HWAVEOUT _ghWaveOut = NULL;

static volatile int which = 0;
static WAVEHDR WaveHdr[2];
static char outbuf[2][4410 * 4];

static int play_init(long rate, int chanel)
{
	int err = 0;
	WAVEFORMATEX waveform;
	waveform.wFormatTag		= WAVE_FORMAT_PCM;
	waveform.nChannels		= chanel;
	waveform.nSamplesPerSec	= rate;
	waveform.nBlockAlign	= 16 * chanel / 8;
	waveform.wBitsPerSample	= 16;
	waveform.cbSize			= 0;
	waveform.nAvgBytesPerSec = rate * chanel * 16 / 8;

	_ghEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	err = waveOutOpen(&_ghWaveOut, WAVE_MAPPER, &waveform, (DWORD)_ghEvent, 0, CALLBACK_EVENT);

	memset(WaveHdr, 0, sizeof(WaveHdr));
	WaveHdr[0].dwLoops  = 1;
	WaveHdr[1].dwLoops  = 1;
	waveOutPrepareHeader(_ghWaveOut, &WaveHdr[0], sizeof(WAVEHDR));
	waveOutPrepareHeader(_ghWaveOut, &WaveHdr[1], sizeof(WAVEHDR));

	return err;
}

static int play_wait(int which)
{
	LPWAVEHDR pWaveHdr = &WaveHdr[which];

	pWaveHdr = &WaveHdr[which];
	while(pWaveHdr->dwFlags == 0x12)
		WaitForSingleObject(_ghEvent, -1);

	return 0;
}

static int play_update(const char buf[], int len)
{
	int err = 0;
	LPWAVEHDR pWaveHdr = &WaveHdr[which];

	pWaveHdr->lpData          = (LPTSTR)buf ;
	pWaveHdr->dwBufferLength  = len;
	err = waveOutWrite(_ghWaveOut, pWaveHdr, sizeof (WAVEHDR));
	which = !which;

	return err;
}

static int play_stream(mpg123_handle *mh)
{
	int n;
	int err;
	int done;

	long rate;
	int channels, enc;

	err = mpg123_decode(mh, NULL, 0,
			outbuf[which], sizeof(outbuf[which]), &done);
	mpg123_getformat(mh, &rate, &channels, &enc);
	play_init(rate, channels);

	do {
		play_wait(which);
		err = mpg123_decode(mh, NULL, 0,
				outbuf[which], sizeof(outbuf[which]), &done);
		if (err != MPG123_ERR)
			play_update(outbuf[which], done);
	} while (err == MPG123_OK);

	if (err == MPG123_ERR)
		printf("err = %s\n", mpg123_strerror(mh));

	play_wait(!which);
	waveOutReset(_ghWaveOut);
	waveOutClose(_ghWaveOut);
	CloseHandle(_ghEvent);
	return 0;
}

int main(int argc, char *argv[])
{ 
	int i;
	int err = 0;
	mpg123_handle *mh;

	mpg123_init();
	mh = mpg123_new(NULL, &err);
	assert(mh != NULL);

	for (i = 1; i < argc; i++) {
		err = mpg123_open(mh, argv[i]);
		assert(err == MPG123_OK);

		play_stream(mh);
		mpg123_close(mh);
	}

	mpg123_delete(mh);
	mpg123_exit();
	return 0;
}
