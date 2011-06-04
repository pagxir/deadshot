#ifndef _CANTAINER_H_
#define _CANTAINER_H_
struct cantainer;

struct cantainer *cantainer_box(struct cantainer *fp, size_t count);
struct cantainer *cantainer_file(const char *path);

int cantainer_read(struct cantainer *cp, void *buf, size_t count);
int cantainer_seek(struct cantainer *cp, size_t count);
int cantainer_close(struct cantainer *cp);

#endif

