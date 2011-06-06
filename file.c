#include <stdio.h>
#include <stdlib.h>

static const char * file_type[] = {
	"x-jpg", "x-png", "x-gif", "x-gif", NULL
};

static const char * file_magic[] = {
	"FFD8FFE0****4A46494600",
   	"89504E470D0A1A0A",
	"474946383761",
	"474946383961",
	NULL
};

int test_magic(const char * bxf, const char * magic)
{
	while (*bxf && *magic) {

		if (*magic == '*') {
			magic++, bxf++;
			continue;
		}

		if (*magic == *bxf) {
			magic++, bxf++;
			continue;
		}
	   
		break;
	}

	return *magic;
}

int ident_file_type(const char * path)
{
	int i;
	int type;
	int count;
	FILE * file; 
	char buf[256];
	char bxf[1513];
	unsigned char * sp; char * dp;
	
	file = fopen(path, "rb");

	count = 0;
	if (file != NULL) {
		count = fread(buf, 1, sizeof(buf), file);
	   	fclose(file);
	}

	dp = bxf;
   	sp = (unsigned char *)buf;
	for (i = 0; i < count; i++) {
		sprintf(dp, "%02X", *sp);
		dp += 2, sp++;
	}
	*dp++ = 0;

	type = 0;
	for (i = 0; file_magic[i]; i++) {
		if (test_magic(bxf, file_magic[i]) == 0) {
			printf("image/%s: %s\n", file_type[i], path);
			type = (i + 1);
			break;
		}
	}

	return type;
}

int main(int argc, char * argv[])
{
	int i;
	int type;

	for (i = 1; i < argc; i++) 
		type = ident_file_type(argv[i]);

	exit(type);
	return type;
}

