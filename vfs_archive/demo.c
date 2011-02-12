#include <stdio.h>
#include "vfsfs.h"
#include "vfsfat.h"

int main(int argc, char *argv[])
{
    int count;
    char buf[1024];
    struct vfs_node file;

    if (argc < 2) {
        printf("too few argument!\n");
        return -1;
    }

    if (vfs_mount(argv[1], &fat_fs)) {
        printf("vfs_mount fail\n");
       	return -1;
    }

    if (vfs_open(argv[2], &file)) {
        printf("vfs_open fail\n");
        return -1;
    }

    FILE * fout = fopen(argc < 4? "fout.txt": argv[3], "wb");
    if (fout != NULL) {
       	while (!vfs_read(&file, buf, sizeof(buf), &count) && count > 0)
	    fwrite(buf, 1, count, fout);
       	fclose(fout);
    }

    if (vfs_close(&file)) {
        printf("vfs_close fail\n");
        return -1;
    }

    printf("test success\n");
    return 0;
}

