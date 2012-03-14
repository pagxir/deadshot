#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>


#include "vfsfs.h"
#include "vfsfat.h"

#define VFS_MALLOC(t, n) t *n = (t *)malloc(sizeof(t))

struct fat32_struct {
    uint8_t jmp[3];
    uint8_t oem[8];
    uint8_t bpb[53];
    uint8_t bpbx[26];
    uint8_t boot[420];
    uint8_t magic[2];
}__attribute__((packed));

struct fat32_bpb {
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sector;
    uint8_t number_of_FAT;
    uint16_t root_entries;
    uint16_t small_sector;
    uint8_t media_descriptor;
    uint16_t sectors_per_fat;
    uint16_t sectors_per_track;
    uint16_t number_of_head;
    uint32_t hidden_sectors;
    uint32_t large_sector;
    uint32_t sectors_per_fat32;
    uint16_t extended_flags;
    uint16_t filesystem_version;
    uint32_t root_cluster_number;
    uint16_t system_info_sector_number;
    uint16_t backup_sectors;
    uint16_t reserverd[6];
}__attribute__((packed));

struct fat32_bpbx {
    uint8_t driver_number;
    uint8_t reserver;
    uint8_t extended_boot_signature;
    uint32_t volume_serial_number;
    uint8_t volume_label[11];
    uint8_t filesystem_type[8];
}__attribute__((packed));

struct fat_struct {
    uint8_t jmp[3];
    uint8_t oem[8];
    uint8_t bpb[25];
    uint8_t bpbx[26];
    uint8_t boot[448];
    uint8_t magic[4];
}__attribute__((packed));

struct fat_bpb {
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sector;
    uint8_t number_of_FAT;
    uint16_t root_entries;
    uint16_t small_sector;
    uint8_t media_desc;
    uint16_t sectors_per_fat;
    uint16_t sectors_per_track;
    uint16_t number_of_heads;
    uint32_t hidden_sectors;
    uint32_t large_sectors;
}__attribute__((packed));

struct fat_bpbx {
    uint8_t physical_drive_number;
    uint8_t reserverd;
    uint8_t extended_boot_signature;
    uint32_t volume_serial_number;
    uint8_t volume_label[11];
    uint8_t filesystem_type[8];
}__attribute__((packed));

struct fat_entry {
    uint8_t name[8];
    uint8_t fext[3];
    uint8_t attribute;
    uint8_t reserverd[8];
    uint16_t cluster_high;
    uint16_t mtime;
    uint16_t mdate;
    uint16_t cluster_entry;
    uint32_t length;
}__attribute__((packed));

struct fat_opvector;

struct fatfs_priv {
    FILE *fimage;
    size_t bytes_per_sector;
    size_t sectors_per_cluster;
    size_t first_cluster_sector;
    size_t reserved_sector;

    size_t sectors_per_fat;
    size_t number_of_FAT;
    size_t root_entries;

    struct fat_opvector *opvector;
};

struct fatfs_dirent {
    struct fatfs_priv *fs;
    size_t lseek;

    size_t cluster;
    size_t offset;
    size_t length;

    size_t entry;
    size_t flag;
};

struct fat_opvector {
    size_t fat_max_cluster;
    size_t fat_cluster_mask;
    int (*fat_next_cluster)(struct fatfs_priv *, size_t , size_t *);
};

extern struct fat_opvector fat12fs_opvector;
extern struct fat_opvector fat16fs_opvector;
extern struct fat_opvector fat32fs_opvector;
extern struct vfs_opvector fatfs_vops;

int fat_read_sector(struct fatfs_priv *fsop, size_t sector, void * buf)
{
    assert(fsop->bytes_per_sector >= 512);
    if (0 != fseek(fsop->fimage, sector * fsop->bytes_per_sector, SEEK_SET)) {
        printf("__fat_read_sector: %d\n", sector);
        return -1;
    }
    return fread(buf, fsop->bytes_per_sector, 1, fsop->fimage);
}

int fat_read_cluster(struct fatfs_priv *fsop, size_t cluster, void *buf)
{
    int i = 0;
    size_t cpcnt = 0;
    char *p = (char*)buff;

    size_t sector = fsop->first_cluster_sector;
    sector += (cluster - 2) * fsop->sectors_per_cluster;
    assert(fsop->sectors_per_cluster > 0);

    for (i = 0; i < fsop->sectors_per_cluster; i++) {
        if (fat_read_sector(fsop, sector, p + cpcnt) == -1) {
            printf("fat_read_sector: %d\n", sector);
            return -1;
        }
        cpcnt += fsop->bytes_per_sector;
        sector++;
    }

    return 0;
}

int fat_next_cluster32(struct fatfs_priv *fsop, size_t cluster, size_t *pcluster)
{
    int count;
	size_t bytecnt_in_sector;
    size_t fat_start = fsop->reserved_sector;
    size_t sectorcnt = (cluster * 4) / fsop->bytes_per_sector;
    uint32_t *sector_buffer = (uint32_t *)malloc(fsop->bytes_per_sector);

    assert(sector_buffer != NULL);
    if (-1 == fat_read_sector(fsop, fat_start + sectorcnt, sector_buffer)) {
        free(sector_buffer);
        return -1;
    }
    bytecnt_in_sector = (cluster * 4) - (fsop->bytes_per_sector * sectorcnt);
    *pcluster = sector_buffer[bytecnt_in_sector >> 2];
    free(sector_buffer);
    return 0;
}

int fat_next_cluster16(struct fatfs_priv *fsop, size_t cluster, size_t *pcluster)
{
    int count;
	size_t bytecnt_in_sector;
    size_t fat_start = fsop->reserved_sector;
    size_t sectorcnt = (cluster*2)/(fsop->bytes_per_sector);
    uint16_t *sector_buffer = (uint16_t *)malloc(fsop->bytes_per_sector);

    assert(sector_buffer != NULL);
    if (-1 == fat_read_sector(fsop, fat_start+sectorcnt, sector_buffer)) {
        free(sector_buffer);
        return -1;
    }

    bytecnt_in_sector = (cluster * 2) - (fsop->bytes_per_sector * sectorcnt);
    *pcluster = sector_buffer[bytecnt_in_sector >> 1];
    free(sector_buffer);
    return 0;
}

int fat_next_cluster12(struct fatfs_priv *fsop, size_t cluster, size_t *pcluster)
{
    int count;
    size_t fat_start = fsop->reserved_sector;

    size_t bitcnt = cluster * 12;
    size_t sectorcnt = bitcnt / (fsop->bytes_per_sector * 8);

    uint8_t *sector_buffer = (uint8_t *)malloc(fsop->bytes_per_sector * 2);

    assert(sector_buffer != NULL);
    if (-1 == fat_read_sector(fsop, fat_start + sectorcnt, sector_buffer)) {
        free(sector_buffer);
        return -1;
    }

    size_t bitcnt_in_sector = bitcnt - (fsop->bytes_per_sector * 8 * sectorcnt);
    size_t bytecnt_in_sector = bitcnt_in_sector / 8;

    if (bytecnt_in_sector + 1 == fsop->bytes_per_sector) {
	   	if (-1 == fat_read_sector(fsop,
				   	fat_start + sectorcnt + 1, sector_buffer + fsop->bytes_per_sector)) {
		   	free(sector_buffer);
		   	return -1;
	   	}
   	}

    uint8_t *fat_cluster = (sector_buffer + bytecnt_in_sector);
    uint32_t retval = fat_cluster[0] | (fat_cluster[1] << 8);
    free(sector_buffer);
    *pcluster = (bitcnt_in_sector & 0x7) ? (retval >> 4): (retval & 0xFFF);
    return 0;
}

#define IS_FILE(flag) (((flag) & 0x18) == 0)
#define IS_DIR(flag) ((flag) & 0x10)

int fatfs_pread(struct fatfs_dirent *file, void *buf, size_t count, size_t off)
{
    if (!IS_DIR(file->flag)) {
        if (off > file->length)
            return -1;
        if (off + count > file->length)
            count = file->length - off;
    }

    if (count == 0)
        return 0;

    if (off < file->offset) {
        file->cluster = file->entry;
        file->offset = 0;
    }

    size_t i;
    struct fatfs_priv *fs = (struct fatfs_priv *)file->fs;
    size_t bytes_per_cluster = (fs->bytes_per_sector * fs->sectors_per_cluster);
    size_t cluster_count = (offset - file->offset) / bytes_per_cluster;

    struct fat_opvector *opv = fs->opvector;
    while (cluster_count > 0) {
        size_t cluster;
        if ((*opv->fat_next_cluster)(fs, file->cluster, &cluster) == -1) {
            return -1;
        }
        if (cluster >= opv->fat_max_cluster) {
            return 0;
        }
        file->offset += bytes_per_cluster;
        file->cluster = cluster;
        cluster_count--;
    }

    char *cluster_buffer = (char *)malloc(bytes_per_cluster);
    assert(cluster_buffer);

    if (fat_read_cluster(fs, file->cluster, cluster_buffer)) {
        free(cluster_buffer);
        return -1;
    }

    size_t cluster_offset = off - file->offset;
    size_t cpcnt = bytes_per_cluster > cluster_offset + count?
        count: bytes_per_cluster - cluster_offset;
    memcpy(buf, cluster_buffer + cluster_offset, cpcnt);
    free(cluster_buffer);
    off += cpcnt;
    count -= cpcnt;

    int hr = 0;

    while (off < file->length && count > 0) {
        if ((hr = fatfs_pread(file, (char*)buf + cpcnt, count, off)) == -1) {
            return -1;
        }
        if (hr == 0) {
            break;
        }
        off += hr;
        count -= hr;
        cpcnt += hr;
    }

    return cpcnt;
}

int dirent_trim(const char * buf, size_t count)
{
    const char *p = buf;
    const char *end = buf + count;
    while(p < end && *p && *p != ' ')p++;
    return (p - buf);
}

int fat_dirent_lookup(struct fat_entry *dirents, size_t dpcnt,
        const char *path, struct fat_entry *dirent)
{
    char name[13];
    size_t j, cpcnt, cpcntext;

    for (j = 0; j < dpcnt; j++) {
        cpcnt = dirent_trim(dirents[j].name, 8);
        if (cpcnt > 0) {
            strncpy(name, dirents[j].name, cpcnt);
            cpcntext = dirent_trim(dirents[j].fext, 3);
            cpcntext && (name[cpcnt++] = '.');
            strncpy(name + cpcnt, dirents[j].fext, cpcntext);
            name[cpcnt + cpcntext] = 0;
            if (!strcmp(path, name)) {
                *dirent= dirents[j];
                return 0;
            }
        }
    }

    return -1;
}


static int fatfs_root(struct fatfs_priv *fsop,
	const char *name, struct vfs_node *dir)
{
    int idx, count;

    idx = fsop->reserved_sector;
    idx += fsop->sectors_per_fat * fsop->number_of_FAT;

    struct fat_entry entry;
    VFS_MALLOC(struct fatfs_dirent, dirent);
    char *sector_buffer = (char *)malloc(fsop->bytes_per_sector);

    for (count = 0; count < fsop->root_entries; idx++) {
        if (0 >= fat_read_sector(fsop, idx, sector_buffer)) {
            free(sector_buffer);
            free(dirent);
            return -1;
        }

        size_t dpcnt = fsop->bytes_per_sector / 32;
        if (dpcnt + count > fsop->root_entries)
            dpcnt = fsop->root_entries - count;

        struct fat_entry *dirents;
        dirents = (struct fat_entry *)sector_buffer;

        if (0 == fat_dirent_lookup(dirents, dpcnt, name, &entry)) {
            dirent->length= entry.length;
            dirent->entry = entry.cluster_entry;
            dirent->flag  = entry.attribute;
            dirent->fs = fsop;
            dir->vops = &fatfs_vops;
            dir->priv = dirent;
            free(sector_buffer);
            return 0;
        }
        count += dpcnt;
    }
    free(sector_buffer);
    free(dirent);
    return -1;
}

static int fatfs_lookup(void *priv, const char *name, struct vfs_node *dir)
{
    struct fatfs_dirent *dirent = (struct fatfs_dirent *)priv;
    struct fatfs_priv   *fsop   = dirent->fs;

    size_t bytes_per_cluster = (fsop->bytes_per_sector * fsop->sectors_per_cluster);
    char *cluster_buffer = (char *)malloc(bytes_per_cluster);

    if (dirent->flag & 0xFF00) {
        return fatfs_root(fsop, name, dir);
    }else if (!IS_DIR(dirent->flag)) {
        return -1;
    }

    size_t valid_cluster = dirent->entry;
    size_t dpcnt = bytes_per_cluster / 32;
    struct fat_entry *dirents, entry;
    dirents = (struct fat_entry *)cluster_buffer;
    
    struct fat_opvector *opv = fsop->opvector;
    while (valid_cluster < opv->fat_max_cluster) {
        size_t cluster;
        if (-1 == fat_read_cluster(fsop, valid_cluster, cluster_buffer)) {
            free(cluster_buffer);
            return -1;
        }

        if (0 == fat_dirent_lookup(dirents, dpcnt, name, &entry)) {
            VFS_MALLOC(struct fatfs_dirent, dirent);
            dirent->length = entry.length;
            dirent->entry  = entry.cluster_entry| (entry.cluster_high << 16);
            dirent->entry &= opv->fat_cluster_mask;
            printf("found: %d\n", dirent->entry);
            dirent->flag   = entry.attribute;
            dirent->fs = fsop;
            dir->vops = &fatfs_vops;
            dir->priv = dirent;
            free(cluster_buffer);
            return 0;
        }
        
        if (-1 == (*opv->fat_next_cluster)(fsop, valid_cluster, &cluster)) {
            free(cluster_buffer);
            return -1;
        }
        valid_cluster = cluster;
    }

    free(cluster_buffer);
    return -1;
}

static int fatfs_open(void *priv)
{
    struct fatfs_dirent *dirent;
    dirent = (struct fatfs_dirent *)priv;
    dirent->cluster = dirent->entry;
    dirent->offset = 0;
    dirent->lseek = 0;
    return 0;
}

static int fatfs_read(void *priv, void *buf,
        size_t count, size_t *pcluster)
{
    struct fatfs_dirent *dirent = (struct fatfs_dirent*)priv;
    *pcluster = fatfs_pread(priv, buf, count, dirent->lseek);
    if (*pcluster == -1) {
        *pcluster = 0;
    	return -1;
    }
    dirent->lseek += *pcluster;
    return 0;
}

static int fatfs_close(void *priv)
{
    return 0;
}

static int fatfs_mount(const char *image, struct vfs_node *vfsroot)
{
    FILE *fp = NULL;
    char volume[512];

    struct fat_struct *fs16 = (struct fat_struct *)volume;
    struct fat_bpbx *bpbx = (struct fat_bpbx *)fs16->bpbx;
    struct fat_bpb *bpb = (struct fat_bpb *)fs16->bpb;

    struct fat32_struct *fs32 = (struct fat32_struct *)volume;
    struct fat32_bpbx *bpbx32 = (struct fat32_bpbx *)fs32->bpbx;
    struct fat32_bpb *bpb32 = (struct fat32_bpb *)fs32->bpb;

    if (NULL == (fp = fopen(image, "rb"))) {
        printf("open image fail: %s\n", image);
        return -1;
    }

    if (!fread(volume, 512, 1, fp)) {
        printf("read volume fail: %s\n", image);
        goto mount_fail;
    }

    VFS_MALLOC(struct fatfs_priv, fs);
    if (!memcmp(bpbx32->filesystem_type, "FAT32   ", 8)) {
       	fs->reserved_sector     = bpb32->reserved_sector;
        fs->bytes_per_sector    = bpb32->bytes_per_sector;
        fs->sectors_per_cluster = bpb32->sectors_per_cluster;
        fs->sectors_per_fat     = bpb32->sectors_per_fat32;
        fs->number_of_FAT       = bpb32->number_of_FAT;
        fs->root_entries        = bpb32->root_entries;
        size_t cluster0_at_sector= bpb32->reserved_sector;
        cluster0_at_sector += bpb32->number_of_FAT * bpb32->sectors_per_fat32;
        cluster0_at_sector += (bpb32->root_entries * 32) / bpb32->bytes_per_sector;
        fs->first_cluster_sector= cluster0_at_sector;

       	fs->opvector = &fat32fs_opvector;
       	fs->fimage = fp;
    }else if (!memcmp(bpbx->filesystem_type, "FAT16   ", 8)){
       	fs->reserved_sector     = bpb->reserved_sector;
        fs->bytes_per_sector    = bpb->bytes_per_sector;
        fs->sectors_per_cluster = bpb->sectors_per_cluster;
        fs->sectors_per_fat     = bpb->sectors_per_fat;
        fs->number_of_FAT       = bpb->number_of_FAT;
        fs->root_entries        = bpb->root_entries;
        size_t cluster0_at_sector= bpb->reserved_sector;
        cluster0_at_sector += bpb->number_of_FAT * bpb->sectors_per_fat;
        cluster0_at_sector += (bpb->root_entries * 32) / bpb->bytes_per_sector;
        fs->first_cluster_sector= cluster0_at_sector;

       	fs->opvector = &fat16fs_opvector;
       	fs->fimage = fp;
    } else if (!memcmp(bpbx->filesystem_type, "FAT12   ", 8)){
       	fs->reserved_sector     = bpb->reserved_sector;
        fs->bytes_per_sector    = bpb->bytes_per_sector;
        fs->sectors_per_cluster = bpb->sectors_per_cluster;
        fs->sectors_per_fat     = bpb->sectors_per_fat;
        fs->number_of_FAT       = bpb->number_of_FAT;
        fs->root_entries        = bpb->root_entries;
        size_t cluster0_at_sector= bpb->reserved_sector;
        cluster0_at_sector += bpb->number_of_FAT * bpb->sectors_per_fat;
        cluster0_at_sector += (bpb->root_entries * 32) / bpb->bytes_per_sector;
        fs->first_cluster_sector= cluster0_at_sector;

       	fs->opvector = &fat12fs_opvector;
       	fs->fimage = fp;
    } else{
        free(fs);
        goto mount_fail;
    }

    if (fs->root_entries & 0xF) {
        printf("test root_entries fail: %s\n", image);
        goto mount_fail;
    }

    VFS_MALLOC(struct fatfs_dirent, fatfs_root);
    if (memcmp(bpbx32->filesystem_type, "FAT32   ", 8)){
        fatfs_root->fs    = fs;
        fatfs_root->flag  = 0xFF00;
        fatfs_root->entry = 0;
    }else{
        fatfs_root->fs    = fs;
        fatfs_root->flag  = 0x10;
        fatfs_root->entry = bpb32->root_cluster_number;
    }

    vfsroot->priv = fatfs_root;
    vfsroot->vops = &fatfs_vops;
	printf("sectors_per_cluster: %d\n", fs->sectors_per_cluster);
	printf("bytes_per_sector: %d\n", fs->bytes_per_sector);
    return 0;

mount_fail:
    fclose(fp);
    return -1;
}

struct fat_opvector fat12fs_opvector = {
    0xFF0, 0xFFF, fat_next_cluster12
};
struct fat_opvector fat16fs_opvector = {
    0xFFF0, 0xFFFF, fat_next_cluster16
};
struct fat_opvector fat32fs_opvector = {
    0xFFFFFFF0, 0xFFFFFFFF, fat_next_cluster32
};

struct vfs_opvector fatfs_vops = {
    .lookup = fatfs_lookup,
    .close = fatfs_close,
    .read = fatfs_read,
    .open = fatfs_open
};

struct vfs_fs fat_fs = {
    .mount = fatfs_mount
};

