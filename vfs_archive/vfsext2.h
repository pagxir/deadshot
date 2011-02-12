#ifndef _VFSEXT2_H_
#define _VFSEXT2_H_

#define EXT3_N_BLOCKS 15
#define EXT3_NAME_LEN 255

struct ext3_super_block {
	/*00*/ uint32_t s_inodes_count;      /* inodes 计数 */
	uint32_t s_blocks_count;      /* blocks 计数 */
	uint32_t s_r_blocks_count;    /* 保留的 blocks 计数 */
	uint32_t s_free_blocks_count; /* 空闲的 blocks 计数 */
	/*10*/ uint32_t s_free_inodes_count; /* 空闲的 inodes 计数 */
	uint32_t s_first_data_block;  /* 第一个数据 block */
	uint32_t s_log_block_size;    /* block 的大小 */
	int32_t s_log_frag_size;     /* 可以忽略 */
	/*20*/ uint32_t s_blocks_per_group;  /* 每 block group 的 block 数量 */
	uint32_t s_frags_per_group;   /* 可以忽略 */
	uint32_t s_inodes_per_group;  /* 每 block group 的 inode 数量 */
	uint32_t s_mtime;             /* Mount time */
	/*30*/ uint32_t s_wtime;             /* Write time */
	uint16_t s_mnt_count;         /* Mount count */
	int16_t s_max_mnt_count;     /* Maximal mount count */
	uint16_t s_magic;             /* Magic 签名 */
	uint16_t s_state;             /* File system state */
	uint16_t s_errors;            /* Behaviour when detecting errors */
	uint16_t s_minor_rev_level;   /* minor revision level */
	/*40*/ uint32_t s_lastcheck;         /* time of last check */
	uint32_t s_checkinterval;     /* max. time between checks */
	uint32_t s_creator_os;        /* 可以忽略 */
	uint32_t s_rev_level;         /* Revision level */
	/*50*/ uint16_t s_def_resuid;        /* Default uid for reserved blocks */
	uint16_t s_def_resgid;        /* Default gid for reserved blocks */
	uint32_t s_first_ino;         /* First non-reserved inode */
	uint16_t s_inode_size;        /* size of inode structure */
	uint16_t s_block_group_nr;    /* block group # of this superblock */
	uint32_t s_feature_compat;    /* compatible feature set */
	/*60*/ uint32_t s_feature_incompat;  /* incompatible feature set */
	uint32_t s_feature_ro_compat; /* readonly-compatible feature set */
	/*68*/ uint8_t  s_uuid[16];          /* 128-bit uuid for volume */
	/*78*/ char  s_volume_name[16];   /* volume name */
	/*88*/ char  s_last_mounted[64];  /* directory where last mounted */
	/*C8*/ uint32_t s_algorithm_usage_bitmap; /* 可以忽略 */
	uint8_t  s_prealloc_blocks;        /* 可以忽略 */
	uint8_t  s_prealloc_dir_blocks;    /* 可以忽略 */
	uint16_t s_padding1;               /* 可以忽略 */
	/*D0*/ uint8_t  s_journal_uuid[16]; /* uuid of journal superblock */
	/*E0*/ uint32_t s_journal_inum;     /* 日志文件的 inode 号数 */
	uint32_t s_journal_dev;      /* 日志文件的设备号 */
	uint32_t s_last_orphan;      /* start of list of inodes to delete */
	/*EC*/ uint32_t s_reserved[197];    /* 可以忽略 */
};

struct ext3_group_desc
{
	uint32_t bg_block_bitmap;      /* block 指针指向 block bitmap */
	uint32_t bg_inode_bitmap;      /* block 指针指向 inode bitmap */
	uint32_t bg_inode_table;       /* block 指针指向 inodes table */
	uint16_t bg_free_blocks_count; /* 空闲的 blocks 计数 */
	uint16_t bg_free_inodes_count; /* 空闲的 inodes 计数 */
	uint16_t bg_used_dirs_count;   /* 目录计数 */
	uint16_t bg_pad;               /* 可以忽略 */
	uint32_t bg_reserved[3];       /* 可以忽略 */
};

struct ext3_inode {
	uint16_t i_mode;    /* File mode */
	uint16_t i_uid;     /* Low 16 bits of Owner Uid */
	uint32_t i_size;    /* 文件大小，单位是 byte */
	uint32_t i_atime;   /* Access time */
	uint32_t i_ctime;   /* Creation time */
	uint32_t i_mtime;   /* Modification time */
	uint32_t i_dtime;   /* Deletion Time */
	uint16_t i_gid;     /* Low 16 bits of Group Id */
	uint16_t i_links_count;          /* Links count */
	uint32_t i_blocks;               /* blocks 计数 */
	uint32_t i_flags;                /* File flags */
	uint32_t l_i_reserved1;          /* 可以忽略 */
	uint32_t i_block[EXT3_N_BLOCKS]; /* 一组 block 指针 */
	uint32_t i_generation;           /* 可以忽略 */
	uint32_t i_file_acl;             /* 可以忽略 */
	uint32_t i_dir_acl;              /* 可以忽略 */
	uint32_t i_faddr;                /* 可以忽略 */
	uint8_t  l_i_frag;               /* 可以忽略 */
	uint8_t  l_i_fsize;              /* 可以忽略 */
	uint16_t i_pad1;                 /* 可以忽略 */
	uint16_t l_i_uid_high;           /* 可以忽略 */
	uint16_t l_i_gid_high;           /* 可以忽略 */
	uint32_t l_i_reserved2;          /* 可以忽略 */
};

struct ext3_dir_entry_2 {
	uint32_t inode;    /* Inode 号数 */
	uint16_t rec_len;  /* Directory entry length */
	uint8_t  name_len; /* Name length */
	uint8_t  file_type;
	char  name[EXT3_NAME_LEN]; /* File name */
};

#endif

