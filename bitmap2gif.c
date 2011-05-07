#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define X(shift) (1 << (shift))
static int test_mask[32] = {
	X(0x00), X(0x01), X(0x02), X(0x03), X(0x04), X(0x05), X(0x06), X(0x07),
	X(0x08), X(0x09), X(0x0a), X(0x0b), X(0x0c), X(0x0d), X(0x0e), X(0x0f),
	X(0x10), X(0x11), X(0x12), X(0x13), X(0x14), X(0x15), X(0x16), X(0x17),
	X(0x18), X(0x19), X(0x1a), X(0x1b), X(0x1c), X(0x1d), X(0x1e), X(0x1f),
};

struct lzwc_ctx {
	int lc_prefix;
	size_t lc_bpp;
	size_t lc_bitcnt;
	size_t lc_dicode;
	size_t lc_testbl[4096 * 256 / sizeof(size_t) / 8];
	size_t lc_dictbl[4096 * 256];

	size_t lc_outcnt;
	char lc_outbuff[8192 + 4];

	size_t lc_outbit_cnt;
	uint32_t lc_outbit_buff;
};
inline void lzwc_clear(struct lzwc_ctx * ctxp, FILE * fp);

inline void lzwc_restart(struct lzwc_ctx * ctxp)
{
	ctxp->lc_dicode = (1 << ctxp->lc_bpp) + 2;
	ctxp->lc_bitcnt = (ctxp->lc_bpp + 1);
	if (ctxp->lc_dicode >= (1 << ctxp->lc_bitcnt))
		ctxp->lc_bitcnt++;
	memset(ctxp->lc_testbl, 0, sizeof(ctxp->lc_testbl));
}

inline void lzwc_init(struct lzwc_ctx * ctxp, int bpp)
{
	memset(ctxp, 0, sizeof(struct lzwc_ctx));
	ctxp->lc_bpp = bpp;
	ctxp->lc_prefix = -1;
	lzwc_restart(ctxp);
   	lzwc_clear(ctxp, NULL);
}

inline int lzwc_find(struct lzwc_ctx * ctxp, int prefix, int code)
{
	int key = (prefix << 8) | code;
	assert (code < (1 << ctxp->lc_bpp));
	if (ctxp->lc_testbl[key >> 5] &
			test_mask[key & 0x1F])
		return ctxp->lc_dictbl[key];
	return -1;
}

inline int lzwc_update(struct lzwc_ctx * ctxp, int prefix, int code)
{
	int key = (prefix << 8) | code;
	ctxp->lc_testbl[key >> 5] |= test_mask[key & 0x1F];
	ctxp->lc_dictbl[key] = ctxp->lc_dicode++;
	return ctxp->lc_dicode;
}

inline void lzwc_output(struct lzwc_ctx * ctxp, size_t code, FILE *fp)
{
	int i;
	char flag = 0xff;
	size_t mask = (1 << ctxp->lc_bitcnt) - 1;

	ctxp->lc_outbit_buff |= ((code & mask) << ctxp->lc_outbit_cnt);
	ctxp->lc_outbit_cnt += ctxp->lc_bitcnt;

	while (ctxp->lc_outbit_cnt >= 8) {
		char outch = (ctxp->lc_outbit_buff & 0xFF);
		ctxp->lc_outbuff[ctxp->lc_outcnt++] = outch;
		ctxp->lc_outbit_buff >>= 8;
		ctxp->lc_outbit_cnt -= 8;
	}
	if (ctxp->lc_outcnt >= 8192) {
		char * s = ctxp->lc_outbuff;
		while (ctxp->lc_outcnt >= 255) {
		   	fwrite(&flag, 1, 1, fp);
		   	fwrite(s, 1, 255, fp);
		   	ctxp->lc_outcnt -= 255;
			s += 255;
		}
		memmove(ctxp->lc_outbuff, s, ctxp->lc_outcnt);
	}
	if (mask < ctxp->lc_dicode) {
		++ctxp->lc_bitcnt;
	}
}

inline void lzwc_clear(struct lzwc_ctx * ctxp, FILE * fp)
{
	int clear = (1 << ctxp->lc_bpp);
	lzwc_output(ctxp, clear, fp);
}

inline void lzwc_finish(struct lzwc_ctx * ctxp, FILE *fp)
{
	int fin_code = (1 << ctxp->lc_bpp) + 1;
	lzwc_output(ctxp, ctxp->lc_prefix, fp);
	lzwc_output(ctxp, fin_code, fp);

    if (ctxp->lc_outbit_cnt > 0) {
        char outch = (ctxp->lc_outbit_buff & 0xFF);
		ctxp->lc_outbuff[ctxp->lc_outcnt] = outch;
		ctxp->lc_outcnt++;
    }
	
	char flag = 255;
	char * s = ctxp->lc_outbuff;
   	while (ctxp->lc_outcnt >= 255) {
	   	fwrite(&flag, 1, 1, fp);
	   	fwrite(s, 1, 255, fp);
	   	ctxp->lc_outcnt -= 255;
	   	s += 255;
   	}

	if (ctxp->lc_outcnt > 0) {
	   	flag = ctxp->lc_outcnt;
	   	fwrite(&flag, 1, 1, fp);
	   	fwrite(s, 1, ctxp->lc_outcnt, fp);
	}

	flag = 0;
	fwrite(&flag, 1, 1, fp);
}

inline void lzwc_encode(struct lzwc_ctx * ctxp,
	   	const void * buf, int count, int bpp, FILE * fpo)
{
	int code = 0;
	int bitcnt = 0;
	uint32_t bitvals = 0;
	uint32_t bitmask = (1 << bpp) - 1;
	const uint8_t * bitsrc = (const uint8_t *) buf;

	assert (bpp <= ctxp->lc_bpp);
	while (count > 0) {
		if (bitcnt < bpp) {
			bitvals = ((bitvals << 8) | *bitsrc++);
			bitcnt += 8;
		}
		count--;
		bitcnt -= bpp;
		code = (bitvals >> bitcnt) & bitmask;
		if (ctxp->lc_prefix == -1) {
			ctxp->lc_prefix = code;
			continue;
		}
		int prefix1 = lzwc_find(ctxp, ctxp->lc_prefix, code);
		if (prefix1 != -1) {
		   	assert(prefix1 <= ctxp->lc_dicode);
			ctxp->lc_prefix = prefix1;
			continue;
		}
		lzwc_output(ctxp, ctxp->lc_prefix, fpo);
		if (lzwc_update(ctxp, ctxp->lc_prefix, code) < 4096) {
			ctxp->lc_prefix = code;
			continue;
		}
		lzwc_clear(ctxp, fpo);
		ctxp->lc_prefix = code;
		lzwc_restart(ctxp);
	}
}

typedef struct
{
	uint16_t bfType;
	uint32_t bfSize;
	uint16_t bfReserved1;
	uint16_t bfReserved2;
	uint32_t bfOffBits;
}__attribute__((packed)) BITMAPFILEHEADER;

typedef struct
{
	uint32_t biSize;
	int32_t biWidth;
	int32_t biHeight;
	uint16_t biPlanes;
	uint16_t biBitCount;
	uint32_t biCompression;
	uint32_t biSizeImage;
	int32_t biXPelsPerMeter;
	int32_t biYPelsPerMeter;
	uint32_t biClrUsed;
	uint32_t biClrImportant;
} BITMAPINFOHEADER;

typedef struct gifScrDesc{
	uint16_t width;
	uint16_t depth;
	struct GlobalFlag{
		unsigned palBits: 3;
		unsigned sortFlag: 1;
		unsigned colorRes: 3;
		unsigned globalPal: 1;
	}__attribute__((packed))globalFlag;
	uint8_t backGround;
	uint8_t aspect;
}__attribute__((packed))GIFSCRDESC;

typedef struct gifImage{
	uint16_t left;
	uint16_t top;
	uint16_t width;
	uint16_t depth;
	struct LocalFlag{
		unsigned palBits: 3;
		unsigned reserved: 2;
		unsigned sortFlag: 1;
		unsigned interlace: 1;
		unsigned localPal: 1;
	}__attribute__((packed))localFlag;
}__attribute__((packed))GIFIMAGE;

static struct lzwc_ctx __lzwc_ctx;

const char * fncpy(char * dst, size_t len, const char * src, const char * ext)
{
	char ign = 0;
	size_t l = len;
	char * s = dst;
	char * lastchar = &ign;

	strncpy(dst, src, len);
	while (l > 0 && *s != 0) {
		if (*s == '/' || 
				*s == '.' ||
				*s == '\\')
			lastchar = s;
		s++;
		l--;
	}

	if (*lastchar == '.')
		*lastchar = '\0';
	strncat(dst, ext, len);
	return dst;
}

int bitmap2gif(const char * bitmap, const char * gif)
{
	int u, i;
	int count;
	int width, height;
	int width3, total;

	char flag = 0;
	GIFSCRDESC desc;
	GIFIMAGE   gifImage;
	BITMAPFILEHEADER bfhdr;
	BITMAPINFOHEADER bihdr;
	printf("bitmap %s, gif %s\n", bitmap, gif);

	FILE * fin = fopen(bitmap, "rb");
	assert(fin != NULL);
	count = fread(&bfhdr, 1, sizeof(bfhdr), fin);
	assert(count == sizeof(bfhdr));
	count = fread(&bihdr, 1, sizeof(bihdr), fin);
	assert(count == sizeof(bihdr));
	assert(memcmp("BM", &bfhdr.bfType, 2) == 0);
	assert(bihdr.biBitCount <= 8);

	width = bihdr.biWidth;
	width3 = ((width * bihdr.biBitCount / 8)  + 3) & ~0x03;
	height = bihdr.biHeight < 0? -bihdr.biHeight: bihdr.biHeight;
	total  = height * width3;

	printf("biWidth: %d\n", bihdr.biWidth);
	printf("biHeight: %d\n", bihdr.biHeight);
	printf("biBitCount: %d\n", bihdr.biBitCount);
	printf("biClrUsed: %d\n", bihdr.biClrUsed);
	printf("biClrImportant: %d\n", bihdr.biClrImportant);
	printf("bfOffBits: %d\n", bfhdr.bfOffBits);
	printf("HeaderSize: %d\n", sizeof(bihdr) + sizeof(bfhdr));

	char planes[4 * 256];
	count = bfhdr.bfOffBits - sizeof(bihdr) - sizeof(bfhdr); 
	assert(count > 0);
	fread(planes, 1, count, fin);
	char * buf = (char *)malloc(total);
	fread(buf, 1, total, fin);
	assert(buf != NULL);

	FILE * fout = fopen(gif, "wb");
	assert(fout != NULL);
	fwrite("GIF89a", 1, 6, fout);
	desc.width = width;
	desc.depth = height;
	desc.aspect = 0;
	desc.globalFlag.palBits = (bihdr.biBitCount - 1);
	desc.globalFlag.sortFlag = 0;
	desc.globalFlag.colorRes = 0;
	desc.globalFlag.globalPal = 1;
	assert(sizeof(desc) == 7);
	fwrite(&desc, 1, 7, fout);

	char *color_start = planes;
	for (u = 0; u < (1 << bihdr.biBitCount); u++) {
		char color[3];
		color[2] = *color_start++;
		color[1] = *color_start++;
		color[0] = *color_start++;
		fwrite(color, 1, 3, fout);
		color_start++;
	}

#if 0
	/* application control block */
	char acb[] = {
		0x21, 0xFF, 0x0B, 'N', 'E', 'T', 'S', 'C', 'A', 'P', 'E',
		'2', '.', '0', 0x03, 0x01, 0x00, 0x00, 0x00
	};
	fwrite(acb, 1, sizeof(acb), fout);

	/* graphics control block */
	char gcb[] = {0x21, 0xf9, 0x04, 0x08, 0x7f, 0x00, 0x1f, 0x00};
	fwrite(gcb, 1, sizeof(gcb), fout);

	/* text control block */
	char tcb[] = {
		0x21, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00,
		0x10, 0x08, 0x00, 0x15, 0x03,  'k',  'b',  'c', 0x00
	};
	fwrite(tcb, 1, sizeof(tcb), fout);
#endif

	flag = 0x2c;
	fwrite(&flag, 1, 1, fout);

	gifImage.left = 0;
	gifImage.top  = 0;
	gifImage.width = width;
	gifImage.depth = height;
	gifImage.localFlag.localPal = 0;
	gifImage.localFlag.palBits = 0;
	gifImage.localFlag.interlace = 0;
	gifImage.localFlag.sortFlag = 0;
	gifImage.localFlag.reserved = 0;
	assert(9 == sizeof(gifImage));
	fwrite(&gifImage, 1, sizeof(gifImage), fout);

	flag = bihdr.biBitCount;
	flag = (flag > 1)? flag: 2;
	fwrite(&flag, 1, 1, fout);

	int pixel_count = 0;
	int bitcount = bihdr.biBitCount;
	if (height == bihdr.biHeight) {
		lzwc_init(&__lzwc_ctx, flag);
		const char * bitline = &buf[total - width3];
		for (i = 0; i < height; i++) {
			lzwc_encode(&__lzwc_ctx, bitline, width, bitcount, fout);
			pixel_count += width;
			bitline -= width3;
		}
		lzwc_finish(&__lzwc_ctx, fout);
	} else {
		lzwc_init(&__lzwc_ctx, flag);
		const char * bitline = buf;
		for (i = 0; i < height; i++) {
			lzwc_encode(&__lzwc_ctx, bitline, width, bitcount, fout);
			pixel_count += width;
			bitline += width3;
		}
		lzwc_finish(&__lzwc_ctx, fout);
	}
	printf("ftell %lu, total %lu, pixel count %d\n",
		   	ftell(fout), total, pixel_count);

	flag = 0x3b;
	fwrite(&flag, 1, 1, fout);
	free(buf);
	fclose(fout);
	fclose(fin);
	return 0;
}

int main(int argc, char *argv[])
{
	int i;
	char buf[1024];
	for (i = 1; i < argc; i ++) {
		fncpy(buf, sizeof(buf), argv[i], ".gif");
		if (strncmp(buf, argv[i], sizeof(buf)))
			bitmap2gif(argv[i], buf);
	}
	return 0;
}

