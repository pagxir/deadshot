#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ARCH_MAGIC "!<arch>\n"

int save_file(const char * name, FILE * infile, size_t len)
{
	char path[1024];
	
	char * d = path;
	const char * s = name;

	while (*s++) {
		if (s[-1] == '/')
			continue;
		if (d - path < sizeof(path) - 1)
			*d++ = s[-1];
	}

	s = ".obj";
	if (d - path < 4 || strcmp(d - 4, ".obj")) {
		while (*s++)
		   	if (d - path < sizeof(path) - 1)
			   	*d++ = s[-1];
	}
	*d++ = 0;

	char buf[8192];
	int  count = len;
	FILE * outfp = NULL; 

	while (count > 0) {
		int block = count < sizeof(buf)? count: sizeof(buf);
		int n = fread(buf, 1, block, infile);
		if (n == 0)
			break;
		if (count == len && buf[0] == 'L' &&
			   	path[0] != '.' && path[0] != '\0')
			outfp = fopen(path, "wb");
		if (outfp != NULL)
		   	fwrite(buf, 1, n, outfp);
		count -= n;
	}

	if (outfp != NULL)
	   	fclose(outfp);
	return 0;
}

int archive_extract(const char * path)
{
	int len;
	char buf[16 * 4];
	FILE * fp = fopen(path, "rb");
	if (fp == NULL)
		return -1;
	fread(buf, 1, 8, fp);
	if (memcmp(buf, ARCH_MAGIC, 8))
		return -2;
	while (feof(fp) == 0) {
		len = fread(buf, 1, 60, fp);
		buf[len] = 0;
		if (len == 60 && buf[58] == '`' && buf[59] == '\n') {
			int f_size, f_time, f_mode;
			char f_name[1024], f_magic[1024];
			int count = sscanf(buf, "%s%d%d%d%s",
				f_name, &f_time, &f_mode, &f_size, f_magic);
			if (count != 5)
				break;
			time_t t_time = f_time;
			printf("size: %d, mode %d, name %s\n",
				f_size, f_mode, f_name);
			save_file(f_name, fp, f_size);
			fseek(fp, (f_size & 0x01), SEEK_CUR);
			continue;
		}
		printf("magic check fail: %d\n", len);
		break;
	}
	fclose(fp);
	return 0;
}

int main(int argc, char *argv[])
{
	int rc = 0;
	for (int i = 1; i < argc; i++) {
		rc = archive_extract(argv[i]);
		printf("%s %d\n", argv[i], rc);
	}
	return 0;
}
