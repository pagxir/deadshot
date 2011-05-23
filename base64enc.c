#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

int __line_break = 76;

static char base64chars[65] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};

struct b64_enc_up {
	int enc_total;
	int enc_finish;
	int enc_bitcnt;
	int enc_bitvalues;

	int enc_last_in;
	int enc_last_out;
};

struct b64_enc_up * b64_enc_init(struct b64_enc_up * b64p)
{
	b64p->enc_total = 0;
	b64p->enc_finish = 0;
	b64p->enc_bitcnt = 0;
	b64p->enc_bitvalues = 0;

	b64p->enc_last_in = 0;
	b64p->enc_last_out = 0;
	return b64p;
}

size_t b64_enc_trans(struct b64_enc_up *b64p,
		void *dst, size_t l_dst, const void *src, size_t l_src)
{
	size_t orig_dst = l_dst;
	size_t orig_src = l_src;

	int index;
	uint8_t * dst1 = (uint8_t *)dst;
	const uint8_t * src1 = (const uint8_t *)src;

	while (l_src > 0 && l_dst > 0) {
		l_src --;
		b64p->enc_bitcnt += 8;
		b64p->enc_bitvalues <<= 8;
		b64p->enc_bitvalues |= *src1++;

		while (b64p->enc_bitcnt >= 6 && l_dst > 0) {
			b64p->enc_total++;
			b64p->enc_bitcnt -= 6;
			index = (b64p->enc_bitvalues >> b64p->enc_bitcnt);
			*dst1++ = base64chars[index & 0x3F];
			l_dst --;
		}
	}

dec_flush:
	if (b64p->enc_finish) {
		while (b64p->enc_bitcnt > 0 && l_dst > 0) {
			b64p->enc_total++;
			if (b64p->enc_bitcnt < 6)
				b64p->enc_bitcnt = 6;
			b64p->enc_bitcnt -= 6;
			index = (b64p->enc_bitvalues >> b64p->enc_bitcnt);
			*dst1++ = base64chars[index & 0x3F];
			l_dst --;
		}

		if (l_dst > 0) {
			while (l_dst > 0 &&
					(b64p->enc_total & 0x3)) {
				b64p->enc_total++;
				*dst1++ = '=';
				l_dst --;
			}
		}
	}

	b64p->enc_last_in = (orig_src - l_src);
	b64p->enc_last_out = (orig_dst - l_dst);
	return 0;
}

int b64_enc_finish(struct b64_enc_up *b64p, void *dst, size_t l_dst)
{
	b64p->enc_finish = 1;
	return b64_enc_trans(b64p, dst, l_dst, 0, 0);
}

size_t fwrite_format(const void * buf, size_t size,
		size_t count, FILE * file, size_t off)
{
	size_t line_break = __line_break;
	size_t total = size * count;
	const char * src = (const char *)buf;
	size_t line = (off / line_break) + 1;
	size_t chunk_size = (line * line_break - off);
	while (chunk_size <= total) {
		fwrite(src, 1, chunk_size, file);
		fwrite("\r\n", 1, 2, file);
		total -= chunk_size;
		src += chunk_size;
		chunk_size = line_break;
	}
	fwrite(src, 1, total, file);
	return (size * count);
}

int base64transfer(FILE * infile, FILE * outfile)
{
	char buf[64 * 1024];
	char base64text[64 * 1024];
	struct b64_enc_up b64enc;
	size_t off = 0, len = 0, total = 0, count;

	b64_enc_init(&b64enc);
	do {
		len += fread(&buf[len], 1, sizeof(buf) - len, infile);
		off = 0;
		do {
			b64_enc_trans(&b64enc, base64text,
					sizeof(base64text), &buf[off], len - off);
			total += fwrite_format(base64text,
					1, b64enc.enc_last_out, outfile, total);
			off += b64enc.enc_last_in;
		} while (b64enc.enc_last_out > 0);
		assert (len >= off);
		len -= off;
		memmove(buf, &buf[off], len);
	} while ( !feof(infile) );

	do {
		b64_enc_finish(&b64enc, base64text, sizeof(base64text));
		total += fwrite_format(base64text, 1,
				b64enc.enc_last_out, outfile, total);
	} while (b64enc.enc_last_out > 0);

	assert(len == 0);
	return 0;
}

int main(int argc, char * argv[])
{
	char buf[1024];
	FILE * fpin, * fpout;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] != '-')
			continue;
		if (!strcmp(argv[i], "-76"))
			__line_break = 76;
		if (!strcmp(argv[i], "-64"))
			__line_break = 64;
		if (!strcmp(argv[i], "--no-break"))
			__line_break = 0x7FFFFFFF;
	}

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-')
			continue;
		strncpy(buf, argv[i], sizeof(buf));
		strncat(buf, ".b64", sizeof(buf));
		if (strncmp(buf, argv[i], sizeof(buf)) == 0)
			continue;
		if ((fpin = fopen(argv[i], "rb")) &&
				(fpout = fopen(buf, "wb")))
			base64transfer(fpin, fpout);
		fclose(fpout? fpout: stdout);
		fclose(fpin? fpin: stdin);
	}

	return 0;
}

