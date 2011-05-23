#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

struct b64_dec_up {
	int dec_finish;
	int dec_bitcnt;
	int dec_bitvalues;

	int dec_last_in;
	int dec_last_out;
};

struct b64_dec_up * b64_dec_init(struct b64_dec_up *b64p)
{
	b64p->dec_finish = 0;
	b64p->dec_bitcnt = 0;
	b64p->dec_bitvalues = 0;

	b64p->dec_last_in = 0;
	b64p->dec_last_out = 0;
	return b64p;
}

static int get_b64val(const char code, int *valp)
{
	if (code == '+') {
		*valp = 62;
		return 1;
	}

	if (code == '/') {
		*valp = 63;
		return 1;
	}

	if ('A' <= code && code <= 'Z') {
		*valp = code - 'A';
		return 1;
	}

	if ('a' <= code && code <= 'z') {
		*valp = code - 'a' + 26;
		return 1;
	}

	if ('0' <= code && code <= '9') {
		*valp = code - '0' + 52;
		return 1;
	}

	return 0;
}

size_t b64_dec_trans(struct b64_dec_up *b64p,
		void *dst, size_t l_dst, const void *src, size_t l_src)
{
	size_t orig_dst = l_dst;
	size_t orig_src = l_src;

	uint8_t *dst1 = (uint8_t *)dst;
	const uint8_t *src1 = (const uint8_t *)src;

	while (l_src > 0 && l_dst > 0) {
		int value = 0;
		while (!get_b64val(*src1++, &value))
			if (--l_src == 0)
				goto dec_flush;

		l_src --;
		b64p->dec_bitcnt += 6;
		b64p->dec_bitvalues <<= 6;
		b64p->dec_bitvalues |= value;

		while (b64p->dec_bitcnt >= 8 && l_dst > 0) {
			b64p->dec_bitcnt -= 8;
			*dst1++ = (b64p->dec_bitvalues >> b64p->dec_bitcnt);
			l_dst --;
		}
	}

dec_flush:
	if (b64p->dec_finish) {
		while (b64p->dec_bitcnt >= 8 && l_dst > 0) {
			b64p->dec_bitcnt -= 8;
			*dst1++ = (b64p->dec_bitvalues >> b64p->dec_bitcnt);
			l_dst --;
		}
	}

	b64p->dec_last_in = (orig_src - l_src);
	b64p->dec_last_out = (orig_dst - l_dst);
	return 0;
}

int b64_dec_finish(struct b64_dec_up *b64p, void *dst, size_t l_dst)
{
	b64p->dec_finish = 1;
	return b64_dec_trans(b64p, dst, l_dst, 0, 0);
}

int base64transfer(FILE *infile, FILE *outfile)
{
	char buf[64 * 1024];
	char base64text[64 * 1024];
	struct b64_dec_up b64dec;
	size_t off = 0, len = 0, total = 0, count;

	b64_dec_init(&b64dec);
	do {
		len += fread(&buf[len], 1, sizeof(buf) - len, infile);
		off = 0;
		do {
			b64_dec_trans(&b64dec, base64text,
					sizeof(base64text), &buf[off], len - off);
			total += fwrite(base64text, 1, b64dec.dec_last_out, outfile);
			off += b64dec.dec_last_in;
		} while (b64dec.dec_last_out > 0);
		assert (len >= off);
		len -= off;
		memmove(buf, &buf[off], len);
	} while ( !feof(infile) );

	do {
		b64_dec_finish(&b64dec, base64text, sizeof(base64text));
		total += fwrite(base64text, 1, b64dec.dec_last_out, outfile);
	} while (b64dec.dec_last_out > 0);

	assert(len == 0);
	return 0;
}

int main(int argc, char *argv[])
{
	char *dotp, buf[1024];
	FILE * fpin, * fpout;
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-')
			continue;
		strncpy(buf, argv[i], sizeof(buf));
		dotp = strrchr(buf, '.');
		if (dotp != NULL) {
			char *p = dotp;
			while (*p != '\\' &&
					*p != '/' && *p != 0)p++;
			if (*p != 0)
				continue;

			*dotp = 0;
		}

		if ((fpin = fopen(argv[i], "rb")) &&
				(fpout = fopen(buf, "wb")))
			base64transfer(fpin, fpout);
		fclose(fpout? fpout: stdout);
		fclose(fpin? fpin: stdin);
	}
	return 0;
}

