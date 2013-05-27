#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "cantainer.h"

#define min(a, b) ((a) < (b)? (a): (b))

struct cantainer {
	void *upp;
	int (*closep)(void *upp);

	int (*seekp)(void *upp, size_t count);
	int (*readp)(void *upp, void *buf, size_t count);
};

int
cantainer_seek(struct cantainer *cp, size_t count)
{
	assert(cp != NULL);
	return (*cp->seekp)(cp->upp, count);
}

int
cantainer_read(struct cantainer *cp, void *buf, size_t count)
{
	assert(cp != NULL);
	return (*cp->readp)(cp->upp, buf, count);
}

int
cantainer_close(struct cantainer *cp)
{
	assert(cp != NULL);
	(*cp->closep)(cp->upp);
	free(cp);
	return 0;
}

/* file cantainer implement. */

static int
cantainer_file_read(void *upp, void *buf, size_t count)
{
	if (upp != NULL)
		return fread(buf, 1, count, (FILE *)upp);
	return 0;
}

static int cantainer_file_seek(void *upp, size_t count)
{
	if (upp != NULL)
		return fseek((FILE *)upp, count, SEEK_CUR);
	return 0;
}

static int
cantainer_file_close(void *upp)
{
	if (upp != NULL)
		return fclose((FILE *)upp);
	return 0;
}

struct cantainer *
cantainer_file(const char *path)
{
	struct cantainer *cp;

	cp = (struct cantainer *)malloc(sizeof(*cp));
	cp->upp = fopen(path, "rb");
	cp->seekp = cantainer_file_seek;
	cp->readp = cantainer_file_read;
	cp->closep = cantainer_file_close;

	return cp;
}

/* box cantainer implement finish. */
struct box_can_ctx {
	size_t offset;
	size_t length;
	struct cantainer *fatherp;
};

static int
cantainer_box_read(void *upp, void *buf, size_t count)
{
	int bytes;
	struct box_can_ctx *ctxp;
	ctxp = (struct box_can_ctx *)upp;

	if (ctxp != NULL && ctxp->offset < ctxp->length) {
		bytes = min(count, ctxp->length - ctxp->offset);
		if (bytes > 0)
		   	bytes = cantainer_read(ctxp->fatherp, buf, bytes);
		ctxp->offset += bytes;
		return bytes;
	}

	return 0;
}

static int
cantainer_box_seek(void *upp, size_t count)
{
	int bytes;
	struct box_can_ctx *ctxp;
	ctxp = (struct box_can_ctx *)upp;

	if (ctxp != NULL && ctxp->offset < ctxp->length) {
		bytes = min(count, ctxp->length - ctxp->offset);
		cantainer_seek(ctxp->fatherp, bytes);
		ctxp->offset += bytes;
	}

	return 0;
}

static int
cantainer_box_close(void *upp)
{
	struct box_can_ctx *ctxp;

	ctxp = (struct box_can_ctx *)upp;
   	if (ctxp->length > ctxp->offset)
	   	cantainer_seek(ctxp->fatherp, ctxp->length - ctxp->offset);
	return 0;
}

struct cantainer *
cantainer_box(struct cantainer *fatherp, size_t count)
{
	struct cantainer *cp;
	struct box_can_ctx *ctxp;

	cp = (struct cantainer *)malloc(sizeof(*ctxp) + sizeof(*cp));

	cp->upp = (cp + 1);
	cp->readp = cantainer_box_read;
	cp->seekp = cantainer_box_seek;
	cp->closep = cantainer_box_close;

	ctxp = (struct box_can_ctx *)(cp + 1);
   	ctxp->offset = 8;
   	ctxp->length = count;
   	ctxp->fatherp = fatherp;

	return cp;
}

