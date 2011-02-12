#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "vfsfs.h"

static struct vfs_node __vfsroot;

int vfs_mount(const char *image, struct vfs_fs *fs)
{
    assert(fs && fs->mount);
    return fs->mount(image, &__vfsroot);
}

static int __vfs_lookup(struct vfs_node *dir, const char *stp, size_t namelen)
{
    char name[512];
    struct vfs_node namei;

    if (namelen > 0) {
       	memcpy(name, stp, namelen);
       	name[namelen] = 0;
       	if (vfs_lookup(dir, name, &namei))
            return -1;
       	printf("%s\n", name);
       	*dir = namei;
    }

    return 0;
}

int vfs_open(const char *path, struct vfs_node *file)
{
    int error = -1;
    struct vfs_opvector *vops;
    const char *p, *stp = path;
    struct vfs_node dir = __vfsroot;

    for (p = stp; *p; p++) {
        if (*p == '/') {
            if (__vfs_lookup(&dir, stp, p - stp))
                return -1;
            stp = p + 1;
        }
    }

	if (__vfs_lookup(&dir, stp, p - stp))
	    return -1;

    vops = dir.vops;
    *file = dir;
    return vops->open(dir.priv);
}

int vfs_read(struct vfs_node *file, void *buf, size_t count, size_t *ready)
{
    size_t nbyte;
    struct vfs_opvector *vops = file->vops;
    assert(vops && vops->read);
    return vops->read(file->priv, buff, count, ready);
}

int vfs_close(struct vfs_node *file)
{
    struct vfs_opvector *vops = file->vops;
    assert(vops && vops->close);
    return vops->close(file->priv);
}

int vfs_lookup(struct vfs_node *dir, const char *name, struct vfs_node *namei)
{
    assert(dir && namei && name);
    struct vfs_opvector *vops = dir->vops;
    return vops->lookup(dir->priv, name, namei);
}

