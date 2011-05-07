#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

int __line_break = 76;

static char base64chars[65] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};

size_t base64enc(void * dst, size_t l_dst,
	   	const void * src, size_t l_src, int finish)
{
	int bitcnt = 0;
	size_t bitvalues = 0;
	size_t count = l_dst;

	int index;
	uint8_t * dst1 = (uint8_t *)dst;
	const uint8_t * src1 = (const uint8_t *)src;

	while (l_src > 0 && l_dst > 0) {
		bitvalues <<= 8;
		bitvalues |= *src1++;
		bitcnt += 8;
		l_src --;

		while (bitcnt >= 6 && l_dst > 0) {
			index = (bitvalues >> (bitcnt - 6)) & 0x3F;
			*dst1++ = base64chars[index];
			bitcnt -= 6;
			l_dst --;
		}
	}

	if (bitcnt > 0 && l_dst > 0) {
		index = (bitvalues << (6 - bitcnt)) & 0x3F;
		*dst1++ = base64chars[index];
		bitcnt -= 6;
		l_dst --;
	}

	while (l_dst > 0 && finish > 0 &&
			((count - l_dst) & 0x03)) {
		*dst1++ = '=';
		l_dst --;
	}

	if (l_dst > 0) {
		*dst1 = 0;
	}
	return (count - l_dst) >> 2;
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
	size_t off = 0, len = 0, total = 0, count;

	do {
		len += fread(&buf[len], 1, sizeof(buf) - len, infile);
		off = 0;
		do {
			count = base64enc(base64text,
				   	sizeof(base64text), &buf[off], len - off, 0);
			//fwrite(base64text, 4, count, outfile);
			total += fwrite_format(base64text, 4, count, outfile, total);
			off += (count * 3);
		} while (count > 0);
		assert (len >= off);
		len -= off;
		memmove(buf, &buf[off], len);
	} while ( !feof(infile) );

	off = 0;
	do {
		count = base64enc(base64text,
			   	sizeof(base64text), &buf[off], len - off, 1);
	   	//fwrite(base64text, 4, count, outfile);
		total += fwrite_format(base64text, 4, count, outfile, total);
		off += (count * 3);
	} while (off < len && count > 0);

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
 

