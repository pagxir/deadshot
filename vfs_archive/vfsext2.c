#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "vfsext2.h"

static char supper_block[1024 * 2];

void dump_inode(size_t node, size_t gstart,
	   	size_t bsize, FILE *fp, struct ext3_group_desc *descs);

void dump_block(size_t blkno, size_t gstart,
	   	size_t bsize, FILE *fp, struct ext3_group_desc *descs)
{
    int off;
    char buffer[bsize + 1];
    struct ext3_dir_entry_2 *dirent;
    buffer[bsize] = 0;
    fseek(fp, bsize * blkno, SEEK_SET);
    fread(buffer, bsize, 1, fp);

    for (off = 0; off < bsize; off += dirent->rec_len) {
        dirent = (struct ext3_dir_entry_2 *)(buffer + off);
        char mbuf[dirent->name_len + 1];
        memcpy(mbuf, dirent->name, dirent->name_len);
        mbuf[dirent->name_len] = 0;
        if (strcmp(mbuf, ".") && strcmp(mbuf, "..")) {
            printf("node: %d %s\n", dirent->inode, mbuf);
            if (0x2 == dirent->file_type && dirent->inode > 2) {
                dump_inode(dirent->inode, gstart, bsize, fp, descs);
            }
        }
    }
}

void dump_inode(size_t node, size_t gstart,
	   	size_t bsize, FILE *fp, struct ext3_group_desc *descs)
{
    int i;
    struct ext3_super_block *sb;
    sb = (struct ext3_super_block*)(supper_block + 1024);
    /* node 2 group */
    size_t group  = (node - 1) / sb->s_inodes_per_group;
    size_t offset = (node - 1) % sb->s_inodes_per_group;
    printf("inode table: %d\n", descs[group].bg_inode_table);

    /* offset 2 block */
    struct ext3_inode * inodes;
    size_t block = offset * sizeof(struct ext3_inode) / bsize;
    size_t oblock = offset * sizeof(struct ext3_inode) % bsize;

    char block_data[bsize];
    block += descs[group].bg_inode_table;
    fseek(fp, block * bsize, SEEK_SET);
    fread(block_data, bsize, 1, fp);

    inodes = (struct ext3_inode*)(block_data + oblock);
    for (i = 0; i < EXT3_N_BLOCKS; i++) {
        /* printf("%d block: %d\n", i, inodes->i_block[i]); */
        if (inodes->i_block[i])
            dump_block(inodes->i_block[i], gstart, bsize, fp, descs);
    }

    printf("blocks: %d\n", inodes->i_blocks);
    printf("size: %d\n", inodes->i_size);
}

int main(int argc, char * argv[])
{
    FILE *fp = fopen(argv[1], "rb");
    fread(supper_block, 1, sizeof(supper_block), fp);

    struct ext3_super_block *sb;
    sb = (struct ext3_super_block *)(supper_block + 1024);
    printf("%x\n", sb->s_magic);
    size_t bsize = 1 << (sb->s_log_block_size + 10);
    printf("block size: %d\n", bsize);
    printf("block count: %d\n", sb->s_blocks_count);
    printf("block per group: %d\n", sb->s_blocks_per_group);
    size_t cnt = (sb->s_blocks_count-sb->s_first_data_block - 1);
    size_t gcnt = (cnt / sb->s_blocks_per_group) + 1;
    printf("block groups: %d\n", gcnt);

    size_t gstart_block = (2047 / bsize) + 1;

    char group_desc[bsize];
    fseek(fp, gstart_block * bsize, SEEK_SET);
    fread(group_desc, 1, bsize, fp);

    int i;
    struct ext3_group_desc *descs;
    descs = (struct ext3_group_desc *) group_desc;
    for (i = 0; i < gcnt; i++) {
        printf("block bitmap: %d\n", descs[i].bg_block_bitmap);
        printf("inode bitmap: %d\n", descs[i].bg_inode_bitmap);
        printf("inode table: %d\n", descs[i].bg_inode_table);
        printf("free inode count: %d\n", descs[i].bg_free_inodes_count);
        printf("free block count: %d\n", descs[i].bg_free_blocks_count);
        printf("used dirs count: %d\n", descs[i].bg_used_dirs_count);
    }
    dump_inode(2, gstart_block, bsize, fp, descs);
    fclose(fp);
    return 0;
}

