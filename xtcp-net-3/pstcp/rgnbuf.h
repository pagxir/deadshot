#ifndef _RGN_H_
#define _RGN_H_

struct rgnbuf {
	int rb_off;
	int rb_len;
	int rb_size;
	int rb_mask;
	char * rb_data;

	int rb_frgcnt;
	int rb_frgsize;
	int * rb_fragments;
};

int rgn_drop(struct rgnbuf * rb, size_t len);
int rgn_peek(struct rgnbuf * rb, void * buf, size_t count, size_t off);
int rgn_fragment(struct rgnbuf * rb, const void * buf, size_t count, size_t off);

int rgn_reass(struct rgnbuf * rb);
int rgn_get(struct rgnbuf * rb, void * buf, size_t count);
int rgn_put(struct rgnbuf * rb, const void * buf, size_t count);

int rgn_len(struct rgnbuf * rb);
int rgn_rest(struct rgnbuf * rb);
int rgn_size(struct rgnbuf * rb);
int rgn_frgcnt(struct rgnbuf * rb);

void rgn_clear(struct rgnbuf * rb);
void rgn_destroy(struct rgnbuf * rb);

struct rgnbuf * rgn_create(int size);
#endif

