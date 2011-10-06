#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <alsa/asoundlib.h>

#include "mpg123.h"

struct rtphdr_ctx {
	int total;
	int silen;
	int seglen;
}; 

struct mp3stream {
	int total;
	char *bufptr;
};

struct audio_output {
	snd_pcm_t *handle;
	snd_pcm_uframes_t frames;
};

struct mp3play_ctx {
	int space;
	mpg123_handle *file;
	struct audio_output audio;
};

void fixed_begin(unsigned char *buf, int begin)
{
	int type = (buf[1] >> 3) & 0x3;

	if (type == 3) {
		buf[4] = (begin >> 1);
		buf[5] &= 0x7F;
		buf[5] |= (begin << 7) & 0x80;
		return;
	}

	buf[4] = begin;
}

void output_init(struct audio_output *ao)
{
	int dir;
	int error;
	unsigned int freq = 22050;
	snd_pcm_uframes_t frames = 1152 / 2;
	snd_pcm_uframes_t buffer_size = 1152 * 2;

	snd_pcm_hw_params_t *params;

	error = snd_pcm_open(&ao->handle, "default", SND_PCM_STREAM_PLAYBACK, 0);
	assert(error >= 0);

	snd_pcm_hw_params_alloca(&params);
	snd_pcm_hw_params_any(ao->handle, params);
	snd_pcm_hw_params_set_access(ao->handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
	snd_pcm_hw_params_set_format(ao->handle, params, SND_PCM_FORMAT_S16_LE);
	snd_pcm_hw_params_set_channels(ao->handle, params, 1);

	snd_pcm_hw_params_set_rate_near(ao->handle, params, &freq, &dir);
	snd_pcm_hw_params_set_period_size_near(ao->handle, params, &frames, &dir);
	snd_pcm_hw_params_set_buffer_size_near(ao->handle, params, &buffer_size);

	error = snd_pcm_hw_params(ao->handle, params);
	assert(error >= 0);

	snd_pcm_hw_params_get_period_size(params, &frames, &dir);
	ao->frames = frames;

	snd_pcm_hw_params_get_period_time(params, &freq, &dir);
	//ao->freq = freq;

}

void pcm_output_block(struct audio_output *ao, void *buf, size_t len)
{
	int error;

	error = snd_pcm_writei(ao->handle, buf, len / 2);
	if (error == -EPIPE) {
		fprintf(stderr, "underrun occurred\n");
		snd_pcm_prepare(ao->handle);
	} else if (error < 0) {
		const char  *str = snd_strerror(error);
		fprintf(stderr, "error from writei: %s\n", str);
	} else if (error != len / 2) {
		fprintf(stderr, "short write, writei: %d\n", error);
	}
}

void output_clean(struct audio_output *ao)
{
	snd_pcm_drain(ao->handle);
	snd_pcm_close(ao->handle);
}

void decode_init(struct mp3play_ctx *ctx)
{
	int error;

	mpg123_init();
	ctx->file = mpg123_new(NULL, &error);
	assert(ctx->file != NULL);

	error = mpg123_open_feed(ctx->file);
	assert(error == MPG123_OK);

	//mpg123_param(ctx.file, MPG123_RESYNC_LIMIT, -1, 0);
}

void decode_clean(struct mp3play_ctx *ctx)
{
	mpg123_close(ctx->file);
	mpg123_delete(ctx->file);
	mpg123_exit();
}

static void fast_put_block(struct mp3stream *stream, void *buf, size_t len)
{
	memcpy(stream->bufptr, buf, len);
	stream->bufptr += len;
	stream->total += len;
	return;
}

void fast_mp3_decode(mpg123_handle *handle, void *buf, size_t len, struct audio_output *ao)
{
	int error;
	size_t done = 0;

	off_t num = 0;
	size_t bytes = 0;
	unsigned char *output;

	error = mpg123_feed(handle, (unsigned char *)buf, len);
	assert(error == MPG123_OK);

	error = mpg123_decode_frame(handle, &num, &output, &bytes);
	//fprintf(stderr, "ding %d %ld %ld\n", error, num, bytes);

	while (error != MPG123_ERR) {
		switch (error) {
			case MPG123_NEW_FORMAT:
				break;

			case MPG123_NEED_MORE:
				return;

			case MPG123_DONE:
				assert(done == 0);
				return;

			default:
				if (bytes <= 0) {
					fprintf(stderr, "err %d\n", error);
					exit(-1);
				}

				//fprintf(stderr, "bytes %ld\n", bytes);
				pcm_output_block(ao, output, bytes);
				break;
		}

		error = mpg123_decode_frame(handle, &num, &output, &bytes);
	}

	fprintf(stderr, "err = %s\n", mpg123_strerror(handle));
	return;
}

static int fast_rtp_decode(struct mp3play_ctx *ctx, char *buf, size_t size)
{
	char *dat;
	char cache[8192];
	size_t len;
	struct mp3stream stream;
	struct rtphdr_ctx *rtphdr;
	rtphdr = (struct rtphdr_ctx *)buf;

	memset(&stream, 0, sizeof(stream));
	stream.bufptr = cache; 

	buf = (char *)(rtphdr + 1);
	if (rtphdr->total + sizeof(*rtphdr) != size) {
		fprintf(stderr, "invalid frame length: size %ld, total %d, hdrsize %ld\n",
				size, rtphdr->total, sizeof(*rtphdr));
		return -1;
	}

	if (rtphdr->total < rtphdr->silen) {
		fprintf(stderr, "invalid frame length: silen %d, total %d\n",
				rtphdr->silen, rtphdr->total);
		return -1;
	}

	dat = buf + rtphdr->silen;
	len = rtphdr->total - rtphdr->silen;

	fixed_begin(buf, ctx->space);
	if (len < ctx->space) {
		fast_put_block(&stream, dat, len);
		ctx->space -= len;
		memset(dat, 0, ctx->space);
		fast_put_block(&stream, dat, ctx->space);
		ctx->space = len = 0;
	} else {
		fast_put_block(&stream, dat, ctx->space);
		dat += ctx->space;
		len -= ctx->space;
		ctx->space = 0;
	}

	fast_put_block(&stream, buf, rtphdr->silen);
	if (len > rtphdr->seglen) {
		fast_put_block(&stream, dat, rtphdr->seglen);
		ctx->space = 0;
	} else {
		fast_put_block(&stream, dat, len);
		ctx->space += (rtphdr->seglen - len);
	}

	fast_mp3_decode(ctx->file, cache, stream.total, &ctx->audio);
	return 0;
}

int main(int argc, char *argv[])
{
	int size;
	int error;
	int ps_file;
	char buf[8192];
	struct sockaddr_in addr;
	struct mp3play_ctx ctx = {0};

	ps_file = socket(AF_INET, SOCK_DGRAM, 0); 
	assert(ps_file != -1);

	addr.sin_family = AF_INET;
	addr.sin_port   = htons(5566);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	error = bind(ps_file, (struct sockaddr *)&addr, sizeof(addr));
	assert(error == 0);

	size = 3 * 1024;
	//fcntl(ps_file, F_SETFL, O_NONBLOCK);
	setsockopt(ps_file, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	decode_init(&ctx);
	output_init(&ctx.audio);

	for ( ; ; ) {
		size = read(ps_file, buf, 8192);
		if (size <= 0)
			continue;
		//fprintf(stderr, "recv block: %d\n", size);
		fast_rtp_decode(&ctx, buf, size);
		//pcm_output_block(&ctx.audio, buf, size);
	}

	output_clean(&ctx.audio);
	decode_clean(&ctx);
	return 0;
}

