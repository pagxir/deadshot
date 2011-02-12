#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <winsock.h>
#include "zlib.h"

#define CHUNK 65536

typedef struct 
{
    uint16_t bfType;
    uint32_t bfSize;
    uint16_t bfReserved1;
    uint16_t bfReserved2;
    uint32_t bfOffBits;
}__attribute__((packed)) bitmap_file_header_t;

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
} bitmap_info_header_t;

struct png_header_t {
	int width;
	int height;
	unsigned char bitdepth;
	unsigned char colortype;
	unsigned char comdivssion;
	unsigned char filter;
	unsigned char interlace;
} __attribute__((packed));

int png_chunks_list(FILE * file);
int png_chunk1_read(FILE * file);
int png_header_read(FILE * file);
int png_header_print(struct png_header_t * pnghdr, size_t len, int crc);

static int len_src, len_dst;
static char * png_src, * bmp_dst;
static FILE * bmp_file = NULL;
static struct png_header_t png_hdr;

int png_tranafer_init(void);
int png_tranafer_clean(void);
int png_tranafer_dosave(const char * path);

int main(int argc, char *argv[])
{
	int err;
	FILE * file;
	const char * path = argv[1];

	if (argc != 2) {
		printf("usage: %s filename\n", argv[0]);
		return 0;
	}

	file = fopen(path, "rb");
	assert(file != NULL);

	printf("\n\tFile Name : [%s]\n\n", path);
	if (png_header_read(file)) {
		png_tranafer_init();
	   	png_chunks_list(file);
		png_tranafer_dosave("kitty.bmp");
	}

	png_tranafer_clean();
	fclose(file);
	return 0;
}

int  bitmap_byte_per_pixel(int colortype, int bitdepth)
{
	int bitperpixel, byteperline1, byteperpixel;

	bitperpixel = 0;
	if (colortype & 0x0001)
		bitperpixel = bitdepth;

	if (colortype & 0x0004)
		bitperpixel += bitdepth;

	if (colortype & 0x0002)
		bitperpixel += (bitdepth * 3);

	printf("type: %d, depth: %d, %d\n", colortype, bitdepth, bitperpixel);
	return (bitperpixel /  8);
}

int bitmap_getsize()
{
	int line = bitmap_byte_per_pixel(png_hdr.colortype, png_hdr.bitdepth);
	line = (line * png_hdr.width + 3);
	return (line & ~0x3) * png_hdr.height;
}

int png_tranafer_init(void)
{
	int byteperpixel, byteperline;
	byteperpixel = bitmap_byte_per_pixel(png_hdr.colortype, png_hdr.bitdepth);

	byteperline = byteperpixel * png_hdr.width;
	bmp_dst = malloc(byteperline * png_hdr.height + png_hdr.height);
	len_dst = byteperline * png_hdr.height + png_hdr.height;

	png_src = malloc(byteperline * png_hdr.height + png_hdr.height);
	len_src = 0;

	return 0;
}

int png_tranafer_dosave(const char * path)
{
	int err;
	int byteperpixel;

	FILE * file;
	bitmap_file_header_t hdr_file;
	bitmap_info_header_t hdr_info;

	memcpy(&hdr_file.bfType, "BM", 2);
	hdr_file.bfReserved1 = 0;
	hdr_file.bfReserved2 = 0;
	hdr_file.bfOffBits = sizeof(hdr_file);
	hdr_file.bfOffBits += sizeof(hdr_info);
	hdr_file.bfSize = hdr_file.bfOffBits + bitmap_getsize();

	byteperpixel = bitmap_byte_per_pixel(png_hdr.colortype, png_hdr.bitdepth);
	hdr_info.biSize = sizeof(hdr_info);
	hdr_info.biWidth = png_hdr.width;
	hdr_info.biHeight = - png_hdr.height;
	hdr_info.biPlanes = 1;
	hdr_info.biBitCount = byteperpixel * 8;
	hdr_info.biCompression = 0;
	hdr_info.biSizeImage = bitmap_getsize();

	hdr_info.biClrUsed = 0;
	hdr_info.biClrImportant = 0;
	hdr_info.biXPelsPerMeter = 0x1075;
	hdr_info.biYPelsPerMeter = 0x1075;

	assert(len_src < len_dst);
	err = uncompress(bmp_dst, &len_dst, png_src, len_src);
	if (err == Z_OK) {
		int i, j;
		int line;
		char * data;

	   	file = fopen(path, "wb");
	   	fwrite(&hdr_file, sizeof(hdr_file), 1, file);
	   	fwrite(&hdr_info, sizeof(hdr_info), 1, file);

		line = bitmap_byte_per_pixel(png_hdr.colortype, png_hdr.bitdepth);
		line = line * png_hdr.width;

		char old[3];
		data = bmp_dst;
		switch (byteperpixel) {
			case 3:
			   	for (i = 0; i < png_hdr.height; i++) {
				   	for (j = 0; j < png_hdr.width; j++) {
						char t = data[j * 3];
						data[j * 3] = data[j * 3 + 2];
						data[j * 3 + 2] = t;
					}
				   	data += (line + 1);
				}
				break;

			case 4:
			   	for (i = 0; i < png_hdr.height; i++) {
				   	for (j = 0; j < png_hdr.width; j++) {
						char t = data[j * 4];
						data[j * 4] = data[j * 4 + 3];
						data[j * 4 + 3] = t;

						t = data[j * 4 + 1];
						data[j * 4 + 1] = data[j * 4 + 2];
						data[j * 4 + 2] = t;
					}

				   	data += (line + 1);
				}
				break;
		}

		data = bmp_dst;
		for (i = 0; i < png_hdr.height; i++) {
			fwrite(data, 1, line & ~0x0003, file);
			data += (line + 1);
		}

		printf("ZLIB: %d, %d, %d, %d, %d\n",
			   	err, png_hdr.width, png_hdr.height, len_dst, len_src);

#if 0
		FILE * datfile = fopen("a.out", "wb");
		fwrite(png_src, len_src, 1, datfile);
		fclose(datfile);
#endif
	   	fclose(file);
		return 0;
	}

	return 0;
}

int png_tranafer_clean(void)
{
	free(png_src);
	free(bmp_dst);
	return 0;
}

int png_header_read(FILE * file)
{
	int count;
	char data[8];

	int len, crc;
	int png_len[3] = {0};
	struct png_header_t pnghdr;

	unsigned char signature[8] = {
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
	};

	memset(data, 0, sizeof(data));
	count = fread(data, sizeof(data), 1, file);

	if (memcmp(signature, data, sizeof(signature))) {
		return 0;
	}

	if (!fread(png_len, 8, 1, file)) {
		return 0;
	}
   
	if (memcmp(&png_len[1], "IHDR", 4)) {
		return 0;
	}

	len = htonl(png_len[0]);
   	if (len != sizeof(pnghdr) ||
		   	!fread(&pnghdr, len, 1, file)) {
	   	return 0;
	}

	if (!fread(&crc, sizeof(crc), 1, file)) {
	   	return 0;
	}

	printf("LENGTH:[%8d] TYPE:[%s] \n", len, &png_len[1]);
	png_header_print(&pnghdr, len, crc);

	return 1;
}

int png_header_print(struct png_header_t * header, size_t len, int crc)
{
	if (len >= sizeof(png_hdr)) {
	   	memcpy(&png_hdr, header, sizeof(png_hdr));
		png_hdr.width = htonl(png_hdr.width);
		png_hdr.height = htonl(png_hdr.height);
	   	printf("\t---------- IHDR Image header ----------\n");
		printf("\tCHUNK DATA\n");
		printf("\t\tWidth              (4 bytes): [%d]\n", png_hdr.width);
	   	printf("\t\tHeight             (4 bytes): [%d]\n", png_hdr.height);
		printf("\t\tBitdepth           (1 bytes): [%u]\n", png_hdr.bitdepth);
	   	printf("\t\tColor Type         (1 bytes): [%u]\n", png_hdr.colortype);
	   	printf("\t\tCompression method (1 bytes): [%u]\n", png_hdr.comdivssion);
	   	printf("\t\tFilter method      (1 bytes): [%u]\n", png_hdr.filter);
	   	printf("\t\tInterlace method   (1 bytes): [%u]\n", png_hdr.interlace);
	}

	printf("\tCRC : %08x\n", htonl(crc));
	return 0;
}

int png_chunks_list(FILE * file)
{
	int count = 0;

	count = png_chunk1_read(file);
	while (count > 0)
		count = png_chunk1_read(file);

	return count;
}

static char bitmap[CHUNK * 512];
int png_chunk1_read(FILE * file)
{
	int err, i;
	int len, crc, olen;
	int png_len[3] = {0};
	char data[CHUNK];

	if (fread(png_len, 8, 1, file) == 1) {
	   	len = htonl(png_len[0]);
		if (len <= 0 || !fread(data, len, 1, file))
		   	return 0;

	   	if (fread(&crc, 4, 1, file) != 1)
		   	return 0;

#if 1
		printf("LENGTH:[%8d] TYPE:[%s] CRC:[%08x]\n",
			   	len, &png_len[1], htonl(crc));
#endif

		if (memcmp(&png_len[1], "IDAT", 4))
			return 1;

	   	printf("CHUNK LENGTH: %d, CRC:[%08x]\n", len, htonl(crc));

#if 0
		size_t dstlen = len_dst;
		int err = uncompress(bmp_dst, &dstlen, data, len);
		printf("err = %d, %d\n", err, len);
#endif
		memcpy(png_src + len_src, data, len);
		len_src += len;

		return 1;
	}

	return 0;
}

