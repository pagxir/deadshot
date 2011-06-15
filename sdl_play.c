#include <stdlib.h>
#include <math.h>
#include <windows.h>
#include <winsock.h>
#include <SDL/SDL.h>
#include <SDL/SDL_main.h>
#include <assert.h>
#include <unistd.h>
#if 0
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#endif
#include <time.h>
#include "mpg123.h"

#define PSF_INIT 1
#define PSF_STOP 2
#define PSF_PLAY 4

struct play_status {
	int ps_flags;
	float ps_volume;
	const char *ps_path;
	mpg123_handle *ps_handle;
	SDL_AudioSpec ps_desired;
	SDL_AudioSpec ps_obtained;
};

static void play_feed(void *unused, Uint8 * stream, int len)
{
	int err;
	int done;
	SDL_Event event;
	struct play_status *psp;

	psp = (struct play_status *)unused;

	switch(err = mpg123_decode(psp->ps_handle, NULL, 0, stream, len, &done)) {
		case MPG123_OK:
			if (done < len) {
				fprintf(stderr, "stream: %p, %d\n", stream, len);
				memset(stream + done, 0, len - done);
			}
			break;

		case MPG123_NEED_MORE:
			fprintf(stderr, "err = MPG123_NEED_MORE\n");
			break;

		default:
		case MPG123_ERR:
		case MPG123_DONE:
			SDL_PauseAudio(1);
			psp->ps_flags &= ~PSF_PLAY;
			event.type = SDL_USEREVENT;
			SDL_PushEvent(&event);
			break;
	}

	if (psp->ps_volume != 1.0f) {
	   	short *sample = (short *)stream;
		float volume = psp->ps_volume;

	   	while (len > 0) {
		   	*sample = (short)(*sample * volume);
		   	len -= sizeof(short);
		   	sample++;
	   	}
	}
}

static int play_init(struct play_status *psp, mpg123_handle *mpgp)
{
	SDL_AudioSpec *desired, *obtained;
	desired = &psp->ps_desired;
	obtained = &psp->ps_obtained;

	desired->freq = 0;
	desired->format = AUDIO_S16;
	desired->samples = 4096;
	desired->callback = play_feed;
	desired->userdata = psp;
	desired->channels = 0;
	memcpy(obtained, desired, sizeof(*desired));

	psp->ps_flags = 0;
	psp->ps_volume = 1.0;
	psp->ps_handle = mpgp;

	mpg123_param(mpgp, MPG123_RESYNC_LIMIT, -1, 0);
	return 0;
}

static int play_clean(struct play_status *psp)
{
	if (psp->ps_flags & PSF_INIT) {
		psp->ps_flags &= ~PSF_PLAY;
		psp->ps_flags &= ~PSF_STOP;
		psp->ps_flags &= ~PSF_INIT;
	   	SDL_PauseAudio(1);
	   	SDL_CloseAudio();
	}
	return 0;
}

static int play_reset(struct play_status *psp, mpg123_handle *mpgp)
{
	int err;
	int done;

	long rate;
	int channels, enc;
	SDL_AudioSpec *desired, *obtained;

	desired = &psp->ps_desired;
	obtained = &psp->ps_obtained;

	SDL_LockAudio();
	err = mpg123_decode(psp->ps_handle, NULL, 0, NULL, 0, &done);
	mpg123_getformat(psp->ps_handle, &rate, &channels, &enc);
	if (!(psp->ps_flags & PSF_INIT) &&
			psp->ps_obtained.freq != rate ||
			psp->ps_obtained.channels != channels) {
		if (psp->ps_flags & PSF_INIT)
		   	SDL_CloseAudio();
		desired->freq = rate;
		desired->channels = channels;
		SDL_OpenAudio(desired, obtained);
		psp->ps_flags |= PSF_INIT;
	}
   	psp->ps_flags |= PSF_PLAY;
	SDL_UnlockAudio();
	SDL_PauseAudio(0);

	return 0;
}

static int update_caption(struct play_status *psp)
{
	int stop;
	char buf[8192];

	stop = (psp->ps_flags & PSF_STOP);
	sprintf(buf, "idle");
	if (psp->ps_flags & PSF_PLAY) {
		const char *title;
		title = strrchr(psp->ps_path, '/');
		title = title? title: strrchr(psp->ps_path, '\\');
		title = title? title: (psp->ps_path - 1);
	   	sprintf(buf, "%s %s\n", title + 1, stop? "[STOP]": "");
	}
	SDL_WM_SetCaption(buf, 0);

	return 0;
}

int main(int argc, char *argv[])
{
	int i;
	int err = 0;
	int sps, adj;
	int running = 1;
	mpg123_handle *mh;
	SDL_Surface *screen;

	if ((SDL_Init(SDL_INIT_VIDEO| SDL_INIT_AUDIO) == -1)) {
		printf("Could not initialize SDL: %s.\n", SDL_GetError());
		exit(-1);
	}

	screen = SDL_SetVideoMode(400, 400, 16, SDL_SWSURFACE);
	SDL_WM_SetCaption("Audio Example", 0);

	mpg123_init();
	mh = mpg123_new(NULL, &err);
	assert(mh != NULL);

	SDL_Event event;
	struct play_status ctx;

	play_init(&ctx, mh);

	event.type = SDL_USEREVENT;
	SDL_PushEvent(&event);
	i = 1;

	while (running && SDL_WaitEvent(&event)) {
		if (event.type == SDL_KEYDOWN) {
			switch (event.key.keysym.sym) {
				case SDLK_ESCAPE:
					running = 0;
					break;

				case SDLK_q:
					running = 0;
					break;

				case SDLK_SPACE:
				   	SDL_LockAudio();
					if ((ctx.ps_flags & PSF_STOP) == 0) {
						ctx.ps_flags |= PSF_STOP;
						update_caption(&ctx);
						SDL_PauseAudio(1);
					} else if (ctx.ps_flags & PSF_PLAY) {
						ctx.ps_flags &= ~PSF_STOP;
						update_caption(&ctx);
						SDL_PauseAudio(0);
					}
				   	SDL_UnlockAudio();
					break;

				case SDLK_MINUS:
				case SDLK_EQUALS:
				   	SDL_LockAudio();
					if (ctx.ps_flags & PSF_PLAY) {
					   	double base, really, rva_db;
						adj = (event.key.keysym.sym == SDLK_MINUS)? -1: 1;
						mpg123_getvolume(ctx.ps_handle, &base, &really, &rva_db);
					   	mpg123_volume_change(ctx.ps_handle, adj * 0.1);
				   	};
				   	SDL_UnlockAudio();
					break;

				case SDLK_LEFT:
				case SDLK_RIGHT:
				   	SDL_LockAudio();
					if (ctx.ps_flags & PSF_PLAY) {
					   	sps = ctx.ps_obtained.freq;
						adj = (event.key.keysym.sym == SDLK_LEFT)? -10: 10;
					   	mpg123_seek(ctx.ps_handle, adj * sps, SEEK_CUR);
					}
				   	SDL_UnlockAudio();
					break;

				default:
					break;
			}
		} else {
			switch(event.type) {
				case SDL_QUIT:
					running = 0;
					break;

				case SDL_USEREVENT:
					if (ctx.ps_flags & PSF_INIT) {
					   	SDL_LockAudio();
					   	mpg123_close(mh);
					   	SDL_UnlockAudio();
					}

					if (i < argc) {
					   	SDL_LockAudio();
						err = mpg123_open(mh, ctx.ps_path = argv[i++]);
						fprintf(stderr, "%s %d\n", argv[i - 1], err);
						assert(err == MPG123_OK);
						play_reset(&ctx, mh);
					   	SDL_UnlockAudio();
					}
					update_caption(&ctx);
					break;

				default:
					break;
			}
		}
	}

	play_clean(&ctx);
	mpg123_delete(mh);
	mpg123_exit();
	return 0;
}

