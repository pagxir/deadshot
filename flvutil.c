#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "stdint.h"
#include <stdlib.h>

#define FLVF_HEADER 1
#define FLVF_SCRIPT 2

#pragma pack(1)
struct flvhdr {
	char fh_magic[3];
	char fh_version;
	char fh_flags;
	char fh_hlen[4];
	char fh_pads[4];
};

struct taghdr {
	uint8_t th_type;
	uint8_t th_dlen[3];
	uint8_t th_tstamp[3];
	uint8_t th_xstamp;
	uint8_t th_streamid[3];
};

struct flvcombine {
	FILE * fc_file;
	uint32_t fc_flags;
	uint32_t fc_timestamp;
	uint32_t fc_lasttimestamp;
	uint32_t fc_metasize;
	uint32_t fc_videocc;
	uint32_t fc_videosize;
	uint32_t fc_audiocc;
	uint32_t fc_audiosize;
	struct taghdr fc_taghdr;
	struct flvhdr fc_header;
};

struct flv_meta {
	const char *mt_path;
	size_t mt_adjust;
	size_t mt_starttime;
	struct metatag *mt_head;
	struct flv_meta *mt_next;
};

struct metaink {
	char *curp;
	char *limit;
	FILE *outfp;
};

static char tag_mark[3] = {
	0x00, 0x00, 0x09
};

static void convert_byte_order(void *buf, size_t len)
{
	char t;
	char *up = (char *)buf;
	char *dw = (char *)buf + len;

	while (up < dw) {
		t = *--dw;
		*dw = *up;
		*up++ = t;
	}

	return;
}

static void ink_init(struct metaink *ink, char *buf, size_t len)
{
	ink->curp = buf;
	ink->limit = (buf + len);
	return;
}

static int ink_eof(struct metaink *ink)
{
	return (ink->limit == ink->curp);
}

static int ink_len(struct metaink *ink)
{
	int len;
	len = ink->limit - ink->curp;
	assert(len > 0);
	return len;
}

static int ink_get_byte(struct metaink *ink)
{
	int type = 0xFF;

	if (ink->curp >= ink->limit)
		return type;

	type = *ink->curp++;
	return type;
}

static void ink_get_mem(struct metaink *ink, void *buf, size_t len)
{
	if (ink_len(ink) < (int)len) {
		memcpy(buf, ink->curp, ink_len(ink));
		ink->curp = ink->limit;
		return;
	}

	memcpy(buf, ink->curp, len);
	ink->curp += len;
	return;
}

static int ink_get_value(struct metaink *ink)
{
	int val = 0;
	ink_get_mem(ink, &val, sizeof(val));
	convert_byte_order(&val, sizeof(val));
	return val;
}

static double ink_get_double(struct metaink *ink)
{
	double val = 0.0;
	ink_get_mem(ink, &val, sizeof(val));
	convert_byte_order(&val, sizeof(val));
	return val;
}

static int ink_get_str(struct metaink *ink, char **start)
{
	unsigned short t_len = 0;

	if (ink_len(ink) < sizeof(t_len)) {
		ink->curp = ink->limit;
		*start = "";
		return 0;
	}

	ink_get_mem(ink, &t_len, sizeof(t_len));
	convert_byte_order(&t_len, sizeof(t_len));

	if (ink_len(ink) < t_len) {
		ink->curp = ink->limit;
		*start = "";
		return 0;
	}

	*start = ink->curp;
	ink->curp += (long)t_len;
	return t_len;
}

static void ink_skip(struct metaink *ink, size_t skip)
{
	if (ink_len(ink) < (int)skip) {
		ink->curp = ink->limit;
		return;
	}

	ink->curp += skip;
	return;
}

static void ink_put_tag(struct metaink *ink, unsigned char tag)
{
	ink->curp++;
	if (ink->outfp != NULL)
		fwrite(&tag, 1, 1, ink->outfp);
	return;
}

static void ink_put_double(struct metaink *ink, double dvalue)
{
	char buf[8];
	ink->curp += sizeof(dvalue);

	if (ink->outfp != NULL) {
		memcpy(buf, &dvalue, sizeof(dvalue));
		convert_byte_order(buf, sizeof(buf));
		fwrite(buf, 8, 1, ink->outfp);
	}

	return;
}

static void ink_put_string(struct metaink *ink, const char *title)
{
	uint16_t len;

	ink->curp += 2;
	ink->curp += strlen(title);

	if (ink->outfp != NULL) {
		len = strlen(title);
		convert_byte_order(&len, sizeof(len));
		fwrite(&len, 2, 1, ink->outfp);
		len = strlen(title);
		fwrite(title, len, 1, ink->outfp);
	}

	return;
}

static void ink_put_boolean(struct metaink *ink, int bvalue)
{
	char val;

	ink->curp++;
	if (ink->outfp != NULL) {
		val = bvalue;
		fwrite(&val, 1, 1, ink->outfp);
	}
	
	return;
}

static void ink_put_stream(struct metaink *ink, void *buf, size_t len)
{
	ink->curp += len;
	if (ink->outfp != NULL)
		fwrite(buf, len, 1, ink->outfp);
	return;
}

static void ink_put_value(struct metaink *ink, int ivalue)
{
	ink->curp += sizeof(ivalue);

	if (ink->outfp != NULL) {
		convert_byte_order(&ivalue, sizeof(ivalue));
		fwrite(&ivalue, sizeof(ivalue), 1, ink->outfp);
	}

	return;
}

struct metatag {
	int tag;
	int bvalue;
	double dvalue;
	char title[64];
	char *textdata;
	struct metatag *next;
	struct metatag *tagdata;
};

static uint32_t buftoint(const void *buf, size_t len)
{
	uint32_t bufint = 0;
	const uint8_t *pval = (const uint8_t *)buf;
	while (len-- > 0)
		bufint = (bufint << 8) + *pval++;
	return bufint;
}

static int dd_copy(FILE * dst_fp, FILE * src_fp, size_t dlen)
{
	size_t len;
	char buf[64 * 1024];
	while (dlen > 0 && !feof(src_fp)) {
		len = fread(buf, 1, dlen < sizeof(buf)? dlen: sizeof(buf), src_fp);
		if (fwrite(buf, 1, len, dst_fp) != len)
			break;
		dlen -= len;
	}
	return dlen;
}

static uint32_t adjtimestamp(struct taghdr *header, uint32_t stampbase)
{
	uint32_t adjtime = stampbase;
	adjtime += buftoint(&header->th_tstamp, sizeof(header->th_tstamp));
	adjtime += (header->th_xstamp << 24);
	header->th_xstamp = (adjtime >> 24);
	header->th_tstamp[0] = (adjtime >> 16);
	header->th_tstamp[1] = (adjtime >> 8);
	header->th_tstamp[2] = (adjtime >> 0);
	return adjtime;
}

static int amf_end(struct metaink *ink)
{
	char *curp = ink->curp;
	char *limitp = ink->limit;

	assert(curp + 3l <= limitp);
	if (memcmp(tag_mark, curp, 3)) {
		return 0;
	}

	return 1;
}

static struct metatag * alloc_tag(int type)
{
	struct metatag *tag;
	tag = (struct metatag *)malloc(sizeof(*tag));
	tag->tag = type;
	tag->bvalue = 0;
	tag->dvalue = 0.0;
	tag->title[0] = 0;
	tag->next = NULL;
	tag->tagdata = NULL;
	tag->textdata = NULL;
	return tag;
}

static struct metatag * amf_value(double value)
{
	struct metatag *tag;
	tag = alloc_tag(0);
	tag->dvalue = value;
	return tag;
}

static struct metatag * amf_boolean(int value)
{
	struct metatag *tag;
	assert(0 == (value & ~0x01));
	tag = alloc_tag(1);
	tag->bvalue = value;
	return tag;
}

struct metatag *
amf_string(char *str, size_t len)
{
	struct metatag *tag;
	tag = alloc_tag(2);
	tag->textdata = (char *)malloc(len + 1);
	memcpy(tag->textdata, str, len);
	tag->textdata[len] = 0;
	return tag;
}

static struct metatag * amf_list(int type, struct metatag *header)
{
	struct metatag *tag;
	tag = alloc_tag(type);
	tag->tagdata = header;
	return tag;
}

static struct metatag * amf_key_pair(char *str,
	size_t len, struct metatag *val)
{
	assert(len < sizeof(val->title));
	memcpy(val->title, str, len);
	val->title[len] = 0;
	return val;
}

static struct metatag * amf_object(struct metaink *ink)
{
	int i;
	int len;
	int type;
	char *str = 0;
	double value;
	struct metatag *header = NULL;
	struct metatag **tailer = &header;

	type = ink_get_byte(ink);
	switch (type) {
		case 0x00:
			value = ink_get_double(ink);
			return amf_value(value);

		case 0x01:
			len = ink_get_byte(ink);
			return amf_boolean(len);

		case 0x02:
			len = ink_get_str(ink, &str);
			return amf_string(str, len);

		case 0x03:
			while (!amf_end(ink)) {
				struct metatag *val, *tag;
				len = ink_get_str(ink, &str);
				val = amf_object(ink);
				tag = amf_key_pair(str, len, val);
				assert(tag != NULL);
				*tailer = tag;
				tailer = &tag->next;
			}

			ink_skip(ink, 3);
			return amf_list(0x03, header);

		case 0x08:
			len = ink_get_value(ink);

			for (i = 0; i < len; i++) {
				struct metatag *val, *tag;
				int ll = ink_get_str(ink, &str);
				val = amf_object(ink);
				tag = amf_key_pair(str, ll, val);
				assert(tag != NULL);
				*tailer = tag;
				tailer = &tag->next;
			}

			return amf_list(type, header);

		case 0x0A:
			len = ink_get_value(ink);

			for (i = 0; i < len; i++) {
				struct metatag *val;
				val = amf_object(ink);
				assert(val != NULL);
				*tailer = val;
				tailer = &val->next;
			}

			return amf_list(0x0A, header);

		default:
			fprintf(stderr, "[fatal] rest data len: %d\n", ink_len(ink));
			fprintf(stderr, "[fatal] unkown tag type: 0x%02X\n", type);
			exit(0);
			break;
	}

	return NULL;
}

static struct metatag * flv_get_item(struct flv_meta *flv,
		const char *keyname)
{
	int cmp;
	const char *title;
	struct metatag *tag, *iter;

	tag = flv->mt_head;
	if (tag == NULL)
		return NULL;

	if (tag->tag != 0x02)
		return NULL;

	title = tag->textdata;
	if (strcmp(title, "onMetaData") != 0)
		return NULL;

	tag = tag->next;
	if (tag->tag != 0x08)
		return NULL;

	iter = tag->tagdata;
	while (iter != NULL) {
		cmp = strcmp(iter->title, keyname);
		if (cmp == 0)
			return iter;
		iter = iter->next;
	}

	return NULL;
}

static void flv_set_value(struct flv_meta *flv,
		const char *keyname, double val)
{
	struct metatag *tag;
	tag = flv_get_item(flv, keyname);
	if (tag != NULL)
		tag->dvalue = val;
	return;
}

static void write_tag_object(struct metatag *tag, struct metaink *ink)
{
	int len;
	struct metatag *iter;

	ink_put_tag(ink, tag->tag);
	switch (tag->tag) {
		case 0x00:
			ink_put_double(ink, tag->dvalue);
			break;

		case 0x01:
			ink_put_boolean(ink, tag->bvalue);
			break;

		case 0x02:
			ink_put_string(ink, tag->textdata);
			break;

		case 0x03:
			iter = tag->tagdata;
			while (iter != NULL) {
				ink_put_string(ink, iter->title);
				write_tag_object(iter, ink);
				iter = iter->next;
			}

			ink_put_stream(ink, tag_mark, sizeof(tag_mark));
			break;

		case 0x08:
		case 0x0A:
			len = 0;
			iter = tag->tagdata;
			while (iter != NULL) {
				iter = iter->next;
				len ++;
			}
			ink_put_value(ink, len);
			iter = tag->tagdata;
			while (iter != NULL) {
				if (tag->tag == 0x08)
					ink_put_string(ink, iter->title);
				write_tag_object(iter, ink);
				iter = iter->next;
			}
			break;

		default:
			fprintf(stderr, "unkown object tag: %x\n", tag->tag);
			exit(0);
			break;
	}

	return;
}

static void parse_metainfo(struct flv_meta *mt, char *buf, size_t len)
{
	struct metaink ink;
	struct metatag *tag = NULL;
	struct metatag *header = NULL;
	struct metatag **tailer = &header;

	ink_init(&ink, buf, len);
	while (!ink_eof(&ink)) {
		tag = amf_object(&ink);
		if (tag == NULL)
			break;
		*tailer = tag;
		tailer = &tag->next;
	}

	mt->mt_head = header;

	return;
}

static int flv_load_meta(struct flv_meta *mt, const char *path)
{
	int error;
	FILE *flv_in;
	char magic[4] = {0};
	char d_buf[256 * 1024];
	size_t dlen = 0;
	struct flvhdr head;
	struct taghdr taghdr;

	flv_in = fopen(path, "rb");
	if (flv_in == NULL)
		return -1;

	error = -1;
	if (0 == fread(&head, sizeof(head), 1, flv_in)) {
		goto fail;
	}

	memcpy(magic, head.fh_magic, 3);
	if (0 != strcmp("FLV", magic)) {
		goto fail;
	}

#if 0
	printf("magic: %s\n", magic);
	printf("flags: 0x%02x\n", head.fh_flags);
	printf("version: 0x%02x\n", head.fh_version);
	printf("header : %d\n", buftoint(head.fh_hlen, sizeof(head.fh_hlen)));
#endif

	if (0x0 == fread(&taghdr, sizeof(taghdr), 1, flv_in)) {
		goto fail;
	}

	dlen = buftoint(taghdr.th_dlen, sizeof(taghdr.th_dlen));
	if (taghdr.th_type != 0x12) {
		goto fail;
	}

	if (dlen >= sizeof(d_buf)) {
		goto fail;
	}

	if (0x0 == fread(d_buf, 1, dlen, flv_in)) {
		goto fail;
	}

	fprintf(stderr, "dlen %ld\n", dlen);
	parse_metainfo(mt, d_buf, dlen);
	error = 0;

fail:
	fclose(flv_in);
	return error;
}

static int flv_merge_data(struct flvcombine *combine, struct flv_meta *fm)
{
	int scr = 0;
	FILE *fp, *fout;
#ifdef ENABLE_DUMP_METADATA
	FILE *tt = NULL;
#endif
	char magic[4];
	size_t dlen;
	size_t video_index;
	struct flvhdr header;
	struct taghdr tagvideo;
	struct taghdr tagaudio;
	struct taghdr tagheader;

	fp = fopen(fm->mt_path, "rb");
	fout = combine->fc_file;
	if (fp == NULL)
		return 0;

#ifdef ENABLE_DUMP_METADATA
	tt = fopen("meta_data.dat", "wb");
#endif

	video_index = 0;
	memset(magic, 0, sizeof(magic));
	memset(&tagvideo, 0, sizeof(tagvideo));
	memset(&tagaudio, 0, sizeof(tagaudio));

	if ( !fread(&header, sizeof(header), 1, fp) )
		goto failure;

	memcpy(magic, header.fh_magic, 3);
	if ( strcmp("FLV", magic) )
		goto failure;

	memcpy(&combine->fc_header, &header, sizeof(header));
	fm->mt_starttime = combine->fc_timestamp;
#if 0
	printf("magic: %s\n", magic);
	printf("flags: 0x%02x\n", header.fh_flags);
	printf("version: 0x%02x\n", header.fh_version);
	printf("header len: %d\n", buftoint(header.fh_hlen, sizeof(header.fh_hlen)));
#endif

	while (feof(fp) == 0) {
		int skip = 0;

		if ( !fread(&tagheader, sizeof(tagheader), 1, fp) )
			goto failure;

		dlen = buftoint(tagheader.th_dlen, sizeof(tagheader.th_dlen));

		switch (tagheader.th_type) {
			case 0x09:
				if (video_index++ == 0 &&
					(combine->fc_flags & FLVF_HEADER) == 0) {
					skip = 0;
					break;
				}
				combine->fc_videocc ++;
				combine->fc_videosize += (dlen + 11l);
				combine->fc_lasttimestamp = combine->fc_timestamp;
				combine->fc_timestamp = adjtimestamp(&tagheader, fm->mt_starttime);
				tagvideo = tagheader;
				break;

			case 0x08:
				combine->fc_audiocc ++;
				combine->fc_audiosize += (dlen + 11l);
				combine->fc_lasttimestamp = combine->fc_timestamp;
				combine->fc_timestamp = adjtimestamp(&tagheader, fm->mt_starttime);
				tagaudio = tagheader;
				break;

			case 0x12:
				memcpy(&combine->fc_taghdr, &tagheader, sizeof(tagheader));
				if (scr++ != 0)
					goto failure;
				skip = 1;
				break;

			default:
				printf("type %x\n", tagheader.th_type);
				exit(-1);
				break;
		}

		if (skip == 1) {
#ifdef ENABLE_DUMP_METADATA
			dd_copy(tt, fp, dlen);
#else
			fseek(fp, dlen, SEEK_CUR);
#endif
			fseek(fp, 4, SEEK_CUR);
			continue;
		}

		fwrite(&tagheader, sizeof(tagheader), 1, fout);
		fm->mt_adjust = ftell(fout) - ftell(fp);
		if ( dd_copy(fout, fp, dlen + 4))
			break;
	}

failure:
	combine->fc_flags &= ~FLVF_HEADER;
	fclose(fp);

#ifdef ENABLE_DUMP_METADATA
	fclose(tt);
#endif
	return 0;
}

static void flv_update_array(struct flv_meta *fm)
{
	struct metatag *tag;
	struct metatag *old_tag = NULL;

	tag = flv_get_item(fm, "keyframes");
	if (tag == NULL)
		return;

	assert(tag != NULL);
	for (tag = tag->tagdata;
			tag != NULL; tag = tag->next) {
		if (tag->tag != 0x0A || tag->tagdata == NULL
			|| strcmp(tag->title, "filepositions") != 0)
			continue;

		old_tag = tag->tagdata;
		while (old_tag != NULL) {
			old_tag->dvalue += fm->mt_adjust;
			old_tag = old_tag->next;
		}

		break;
	}

	tag = flv_get_item(fm, "keyframes");
	for (tag = tag->tagdata;
			tag != NULL; tag = tag->next) {
		if (tag->tag != 0x0A || tag->tagdata == NULL
			|| strcmp(tag->title, "times") != 0)
			continue;

		old_tag = tag->tagdata;
		while (old_tag != NULL) {
			old_tag->dvalue += (fm->mt_starttime * 1.0 / 1000.0);
			old_tag = old_tag->next;
		}

		break;
	}

	return;
}

static double flv_merge_array(struct flv_meta *fm, const char *tagname)
{
	double retval = 0;
	struct flv_meta *hi;
	struct metatag *tag;
	struct metatag *old_tag = NULL;

	for (hi = fm; hi != NULL; hi = hi->mt_next) {
		tag = flv_get_item(hi, "keyframes");
		if (tag == NULL)
			continue;
		assert(tag != NULL);
#if 0
		printf("keyframes: %p\n", tag);
		printf("tagdata: %p\n", tag->tagdata);
		printf("tag: %p\n", tag->tagdata->tag);
#endif

		for (tag = tag->tagdata;
				tag != NULL; tag = tag->next) {
			if (tag->tag != 0x0A || tag->tagdata == NULL
				|| strcmp(tag->title, tagname) != 0)
				continue;

			if (tag->tagdata->next == NULL)
				continue;

			if (old_tag != NULL)
				old_tag->next = tag->tagdata->next;

			old_tag = tag->tagdata;
			while (old_tag->next != NULL)
				old_tag = old_tag->next;
			retval = old_tag->dvalue;
		}
	}

	return retval;
}

static void flv_update_meta(struct flvcombine *c, struct flv_meta *meta)
{
	int len;
	FILE *fout;
	char buf[4];
	long s1, s2;
	struct taghdr thdr;
	struct flv_meta *iter;
	struct metaink ink = {0};
	struct metatag *tag = meta->mt_head;
	double lastkeyframetimestamp, lastkeyframelocation;

	fout = c->fc_file;
	fseek(fout, 0, SEEK_SET);
	fwrite(&c->fc_header, sizeof(c->fc_header), 1, fout);

	iter = meta;
	while (iter != NULL) {
		flv_update_array(iter);
		iter = iter->mt_next;
	}

	lastkeyframetimestamp = flv_merge_array(meta, "times");
	lastkeyframelocation = flv_merge_array(meta, "filepositions");

	len = c->fc_metasize;
	c->fc_taghdr.th_dlen[0] = len >> 16;
	c->fc_taghdr.th_dlen[1] = len >> 8;
	c->fc_taghdr.th_dlen[2] = len >> 0;
	fwrite(&c->fc_taghdr, sizeof(c->fc_taghdr), 1, fout);

	flv_set_value(meta, "lastkeyframelocation", lastkeyframelocation);
	flv_set_value(meta, "lastkeyframetimestamp", lastkeyframetimestamp);

	memset(&ink, 0, sizeof(ink));
	s1 = ftell(fout);
	ink.outfp = fout;
	while (tag != NULL) {
		write_tag_object(tag, &ink);
		tag = tag->next;
	}
	ink_put_stream(&ink, tag_mark, sizeof(tag_mark));

	buf[0] = len >> 24;
	buf[1] = len >> 16;
	buf[2] = len >> 8;
	buf[3] = len >> 0;
	fwrite(buf, 1, 4, fout);
	s2 = ftell(fout);
	printf("%d %ld\n", c->fc_metasize, s2 - s1);
	return;
}

int cat_flv_video(const char *out_path, int argc, char *argv[])
{
	int i;
	long data_start, data_end;
	struct metaink ink = {0};
	struct metatag *tag;
	struct flvcombine context;
	struct flv_meta *h0, *hi;
	struct flv_meta **tail = &h0;

	for (i = 0; i < argc; i++) {
		hi = (struct flv_meta *)malloc(sizeof(*hi));
		hi->mt_head = NULL;
		hi->mt_next = NULL;
		flv_load_meta(hi, argv[i]);
		*tail = hi;
		 tail = &hi->mt_next;
	}

	tag = h0->mt_head;

	flv_merge_array(h0, "times");
	flv_merge_array(h0, "filepositions");
	while (tag != NULL) {
		write_tag_object(tag, &ink);
		tag = tag->next;
	}
	ink_put_stream(&ink, tag_mark, sizeof(tag_mark));

	tail = &h0;
	for (i = 0; i < argc; i++) {
		hi = (struct flv_meta *)malloc(sizeof(*hi));
		hi->mt_head = NULL;
		hi->mt_next = NULL;
		hi->mt_path = argv[i];
		flv_load_meta(hi, argv[i]);
		*tail = hi;
		 tail = &hi->mt_next;
	}

#if 0
	double lasttimestamp  = flv_all_value(h0, "lasttimestamp");
	double lastkeyframelocation  = flv_all_value(h0, "lastkeyframelocation");
	double lastkeyframetimestamp  = flv_all_value(h0, "lastkeyframetimestamp");
	flv_set_value(h0, "lastkeyframelocation", lastkeyframelocation);
	flv_set_value(h0, "lastkeyframetimestamp", lastkeyframetimestamp);
#endif

	memset(&context, 0, sizeof(context));
	context.fc_file = fopen(out_path, "wb");
	if (context.fc_file == NULL)
		return -1;
	context.fc_flags = FLVF_HEADER;
	context.fc_metasize = (ink.curp - (char *)NULL);
	fseek(context.fc_file, sizeof(struct flvhdr) + sizeof(struct taghdr) + context.fc_metasize + 4, SEEK_SET);
	data_start = ftell(context.fc_file);
	for (hi = h0; hi != NULL; hi = hi->mt_next)
		flv_merge_data(&context, hi);
	data_end = ftell(context.fc_file);
	flv_set_value(h0, "filesize", data_end);
	flv_set_value(h0, "datasize", data_end - data_start);
	flv_set_value(h0, "duration", context.fc_timestamp / 1000.0);
	flv_set_value(h0, "videosize", context.fc_videosize);
	flv_set_value(h0, "audiosize", context.fc_audiosize);
	flv_set_value(h0, "lasttimestamp", context.fc_lasttimestamp / 1000.0);
	flv_update_meta(&context, h0);
	fclose(context.fc_file);
	return 0;
}


int main(int argc, char *argv[])
{
	cat_flv_video("a.flv", argc, argv);
	return 0;
}

