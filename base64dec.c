#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "base64.h"

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
	int i;
	char *dotp, buf[1024];
	FILE * fpin, * fpout;
	for (i = 1; i < argc; i++) {
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

