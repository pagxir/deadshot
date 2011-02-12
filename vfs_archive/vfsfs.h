#ifndef __VFSOP_H__
#define __VFSOP_H__

struct vfs_node;

struct vfs_opvector {
    int (*lookup)(void *, const char *, struct vfs_node *);
    int (*read)(void *, void *, size_t, size_t *);
    int (*close)(void *);
    int (*open)(void *);
};

struct vfs_node {
    struct vfs_opvector *vops;
    void *priv;
};

struct vfs_fs {
    int (*mount)(const char *image, struct vfs_node *vfsroot);
};

int vfs_mount(const char *image, struct vfs_fs *fs);
int vfs_lookup(struct vfs_node *dir, const char *name, struct vfs_node *namei);

int vfs_opendir(const char *path, struct vfs_node *dir);
int vfs_closedir(struct vfs_node *dir);

int vfs_open(const char *path, struct vfs_node *file);
int vfs_read(struct vfs_node *file, void *buf, size_t count, size_t *ready);
int vfs_close(struct vfs_node *file);

#endif

