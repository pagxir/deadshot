#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <windows.h>

#include "dtype.h"
#include "rgnbuf.h"

#define IS_ODD(n)  ((n & 1) != 0)
#define IS_EVEN(n) ((n & 1) == 0)

int rgn_round(int size)
{
	size--;
	size |= (size >> 1);
	size |= (size >> 2);
	size |= (size >> 4);
	size |= (size >> 8);
	size |= (size >> 16);
	return (size + 1);
}

struct rgnbuf * rgn_create(int size)
{
	int frgcnt;
	int frgbufsize;

	char * base;
	struct rgnbuf * rgn;

	size = rgn_round(size);
	frgcnt = (size / 1024);

	frgbufsize = frgcnt * 2 * sizeof(int);
	base = (char *)malloc(sizeof(*rgn) + frgbufsize + size);
	assert(base != NULL);

	rgn = (struct rgnbuf *)base;
	rgn->rb_off = 0;
	rgn->rb_len = 0;
	rgn->rb_size = size;
	rgn->rb_mask = (size - 1);
	rgn->rb_data = (char *)(base + sizeof(*rgn));

	rgn->rb_frgcnt = 0;
	rgn->rb_frgsize = (frgcnt * 2);
	rgn->rb_fragments = (int *)(rgn->rb_data + size);
	return rgn;
}

int rgn_frgcnt(struct rgnbuf * rb)
{
	return rb->rb_frgcnt;
}

void rgn_clear(struct rgnbuf * rb)
{
	rb->rb_len = 0;
	rb->rb_off = 0;
	rb->rb_frgcnt = 0;
}

void rgn_destroy(struct rgnbuf * rb)
{
	void * base = (void *)rb;
	free(base);
}

int rgn_rest(struct rgnbuf * rb)
{
	return (rb->rb_size - rb->rb_len);
}

int rgn_len(struct rgnbuf * rb)
{
	return (rb->rb_len);
}

int rgn_size(struct rgnbuf * rb)
{
	return (rb->rb_size);
}

int rgn_get(struct rgnbuf * rb, void * buf, size_t count)
{
	int part1, off;
	char * pdata = (char *)buf;

	assert(count <= rb->rb_len);
	off = (rb->rb_off & rb->rb_mask);
	part1 = umin(count, (rb->rb_size - off));
	memcpy(buf, rb->rb_data + off, part1);
	memcpy(pdata + part1, rb->rb_data, count - part1);

	rb->rb_len -= count;
	rb->rb_off += count;
	return 0;
}

int rgn_put(struct rgnbuf * rb, const void * buf, size_t count)
{
	int part1, off;
	const char * pdat = (const char *)buf;
	assert(count + rb->rb_len <= (rb->rb_size));
	off = (rb->rb_off + rb->rb_len) & (rb->rb_mask);
	part1 = umin(count, (rb->rb_size) - off);
	memcpy(rb->rb_data, pdat + part1, count - part1);
	memcpy(rb->rb_data + off, buf, part1);
	rb->rb_len += count;

	return count;
}

int rgn_reass(struct rgnbuf * rb)
{
	int count = 0;
	int i, left = 0;
	int * fragments = rb->rb_fragments;
	int end = (rb->rb_len + rb->rb_off);

	for (i = 0; i < rb->rb_frgcnt; i++) {
		if (rb->rb_fragments[i] > end) {
			left = i;
			break;
		}
	}

	if (IS_ODD(left)) {
		count = (rb->rb_fragments[left] - end);
		left++;
	}

	rb->rb_len += count;
	rb->rb_frgcnt -= left;
	memmove(fragments, fragments + left, rb->rb_frgcnt);
	return count;
}

int rgn_fragment(struct rgnbuf * rb, const void * buf, size_t count, size_t off)
{
	int off1, part1;
	char * pdata = (char *)buf;

	int i, left, right;
	int adjstart, adjfinish;
	int * fragments = rb->rb_fragments;

	adjstart = (rb->rb_off + rb->rb_len + off);
	adjfinish = (rb->rb_off + rb->rb_len + off + count);

	assert(count + off <= rgn_rest(rb));
	off1 = (rb->rb_off + rb->rb_len + off) & rb->rb_mask;
	part1 = umin(count, rb->rb_size - off1);

	memcpy(rb->rb_data + off1, buf, part1);
	memcpy(rb->rb_data, pdata + part1, count - part1);

	left = 0;
	right = rb->rb_frgcnt;
	for (i = 0;  i < rb->rb_frgcnt; i++) {
		if (fragments[i] < adjstart) {
			left = (i + 1);
			continue;
		}

		if (fragments[i] > adjfinish) {
			right = i;
			break;
		}
	}

	i = left;
	rb->rb_frgcnt -= (right - left);

	if (i < rb->rb_frgsize &&
			IS_EVEN(left)) {
		rb->rb_frgcnt++;
		i++;
	}

	if (i < rb->rb_frgsize &&
			IS_EVEN(right)) {
		rb->rb_frgcnt++;
		i++;
	}

	assert(i <= rb->rb_frgcnt);
	assert(rb->rb_frgcnt <= rb->rb_frgsize);

	memmove(fragments + i, fragments + right, rb->rb_frgcnt - i);

	i = left;
	if (i < rb->rb_frgsize &&
			IS_EVEN(left)) {
		fragments[i] = adjstart;
		i++;
	}

	if (i < rb->rb_frgsize &&
			IS_EVEN(right)) {
		fragments[i] = adjfinish;
		i++;
	}

	return 0;
}

int rgn_peek(struct rgnbuf * rb, void * buf, size_t count, size_t off)
{
	int off1, part1;
	char * pdata = (char *)buf;

	assert(count + off <= rb->rb_len);
	off1 = (rb->rb_off + off) & rb->rb_mask;
	part1 = umin(count, (rb->rb_size - off1));

	memcpy(buf, rb->rb_data + off1, part1);
	memcpy(pdata + part1, rb->rb_data, count - part1);
	return 0;
}

int rgn_drop(struct rgnbuf * rb, size_t len)
{
	rb->rb_len -= len;
	rb->rb_off += len;
	return 0;
}

