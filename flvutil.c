#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#define FLVF_HEADER 1
#define FLVF_SCRIPT 2

struct flvhdr {
	char fh_magic[3];
	char fh_version;
	char fh_flags;
	char fh_hlen[4];
	char fh_pads[4];
}__attribute__((packed));

struct taghdr {
	uint8_t th_type;
	uint8_t th_dlen[3];
	uint8_t th_tstamp[3];
	uint8_t th_xstamp;
	uint8_t th_streamid[3];
}__attribute__((packed));

struct flvcombine {
	FILE * fc_file;
	uint32_t fc_flags;
	uint32_t fc_timestamp;
	uint32_t fc_filesize;
	double fc_duration;
	int fc_filesize_offset;
	int fc_duration_offset;
};

struct flv_meta {
	struct metatag *mt_head;
	struct flv_meta *mt_next;
};

struct metaink {
	char *curp;
	char *limit;
};

static char tag_mark[6] = {
	0x00, 0x00, 0x09, 0x00, 0x00, 0x09
};

void reserve_mem(void *buf, size_t len)
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

void ink_init(struct metaink *ink, char *buf, size_t len)
{
	ink->curp = buf;
	ink->limit = (buf + len);
	return;
}

int ink_eof(struct metaink *ink)
{
	return (ink->limit == ink->curp);
}

int ink_len(struct metaink *ink)
{
	int len;
	len = ink->limit - ink->curp;
	assert(len > 0);
	return len;
}

int ink_get_byte(struct metaink *ink)
{
	int type = 0xFF;

	if (ink->curp >= ink->limit)
		return type;

	type = *ink->curp++;
	return type;
}

void ink_get_mem(struct metaink *ink, void *buf, size_t len)
{
	if (ink_len(ink) < len) {
		memcpy(buf, ink->curp, ink_len(ink));
		ink->curp = ink->limit;
		return;
	}

	memcpy(buf, ink->curp, len);
	ink->curp += len;
	return;
}

int ink_get_str(struct metaink *ink, char **start)
{
	unsigned short t_len = 0;

	if (ink_len(ink) < sizeof(t_len)) {
		ink->curp = ink->limit;
		*start = "";
		return 0;
	}

	ink_get_mem(ink, &t_len, sizeof(t_len));
	reserve_mem(&t_len, sizeof(t_len));

	if (ink_len(ink) < t_len) {
		ink->curp = ink->limit;
		*start = "";
		return 0;
	}

	*start = ink->curp;
	ink->curp += t_len;
	return t_len;
}

void ink_skip(struct metaink *ink, size_t skip)
{
	if (ink_len(ink) < skip) {
		ink->curp = ink->limit;
		return;
	}

	ink->curp += skip;
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

/* duration, filesize */
	void *
xmemmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
	register char *cur, *last;
	const char *cl = (const char *)l;
	const char *cs = (const char *)s;

	/* we need something to compare */
	if (l_len == 0 || s_len == 0)
		return NULL;

	/* "s" must be smaller or equal to "l" */
	if (l_len < s_len)
		return NULL;

	/* special case where s_len == 1 */
	if (s_len == 1)
		return memchr(l, (int)*cs, l_len);

	/* the last position where its possible to find "s" in "l" */
	last = (char *)cl + l_len - s_len;

	for (cur = (char *)cl; cur <= last; cur++)
		if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
			return cur;

	return NULL;
}

uint32_t buftoint(const void *buf, size_t len)
{
	uint32_t bufint = 0;
	const uint8_t *pval = (const uint8_t *)buf;
	while (len-- > 0)
		bufint = (bufint << 8) + *pval++;
	return bufint;
}

int dd_copy(FILE * dst_fp, FILE * src_fp, size_t dlen)
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

void adjtimestamp(struct taghdr *header, uint32_t stampbase)
{
	uint32_t netval = 0;
	uint32_t adjtime = stampbase;
	adjtime += buftoint(&header->th_tstamp, sizeof(header->th_tstamp));
	adjtime += (header->th_xstamp << 24);
	header->th_xstamp = (adjtime >> 24);
	header->th_tstamp[0] = (adjtime >> 16);
	header->th_tstamp[1] = (adjtime >> 8);
	header->th_tstamp[2] = (adjtime >> 0);
}

int
amf_end(struct metaink *ink)
{
	char *curp = ink->curp;
	char *limitp = ink->limit;

	assert(curp + 6 <= limitp);
	if (memcmp(tag_mark, curp, 6)) {
		return 0;
	}

	return 1;
}

struct metatag *
alloc_tag(int type)
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

struct metatag *
amf_value(double value)
{
	struct metatag *tag;
	tag = alloc_tag(0);
	tag->dvalue = value;
	return tag;
}

struct metatag *
amf_boolean(int value)
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

struct metatag *
amf_list(int type, struct metatag *header)
{
	struct metatag *tag;
	tag = alloc_tag(type);
	tag->tagdata = header;
	return tag;
}

struct metatag *
amf_key_pair(char *str, size_t len, struct metatag *val)
{
	assert(len < sizeof(val->title));
	memcpy(val->title, str, len);
	val->title[len] = 0;
	return val;
}

struct metatag *
amf_object(struct metaink *ink)
{
	int i;
	int len;
	int type;
	int bval;
	char *str = 0;
	double value;
	struct metatag *header = NULL;
	struct metatag **tailer = &header;

	type = ink_get_byte(ink);
	switch (type) {
		case 0x00:
			ink_get_mem(ink, &value, sizeof(value));
			reserve_mem(&value, sizeof(value));
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

			ink_skip(ink, 6);
			return amf_list(0x03, header);

		case 0x08:
			ink_get_mem(ink, &len, sizeof(len));
			reserve_mem(&len, sizeof(len));

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
			ink_get_mem(ink, &len, sizeof(len));
			reserve_mem(&len, sizeof(len));

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

void write_tag_object(struct metatag *tag)
{
	int i;
	int len;
	char *p;
	char buf[9];
	struct metatag *iter;

	switch (tag->tag) {
		case 0x00:
			memcpy(buf + 1, &tag->dvalue, sizeof(tag->dvalue));
			buf[0] = 0x00;
			reserve_mem(buf + 1, 8);
			write(1, buf, 9);
			break;

		case 0x01:
			buf[0] = 0x01;
			buf[1] = tag->bvalue;
			write(1, buf, 2);
			break;

		case 0x02:
			len = strlen(tag->textdata);
			buf[0] = 0x02;
			buf[2] = (len & 0xFF);
			buf[1] = (len >> 8);
			write(1, buf, 3);
			write(1, tag->textdata, strlen(tag->textdata));
			break;

		case 0x03:
			iter = tag->tagdata;
			buf[0] = 0x03;
			write(1, buf, 1);
			while (iter != NULL) {
				len = strlen(iter->title);
				buf[1] = (len & 0xFF);
				buf[0] = (len >> 8);
				write(1, buf, 2);
				write(1, iter->title, len);
				write_tag_object(iter);
				iter = iter->next;
			}
			write(1, tag_mark, 6);
			break;

		case 0x08:
		case 0x0A:
			len = 0;
			iter = tag->tagdata;
			while (iter != NULL) {
				iter = iter->next;
				len ++;
			}
			buf[0] = tag->tag;
			write(1, buf, 1);
			reserve_mem(&len, sizeof(len));
			write(1, &len, sizeof(len));
			iter = tag->tagdata;
			while (iter != NULL) {
				if (tag->tag == 0x08) {
					len = strlen(iter->title);
					buf[1] = (len & 0xFF);
					buf[0] = (len >> 8);
					write(1, buf, 2);
					write(1, iter->title, len);
				}
				write_tag_object(iter);
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

void parse_metainfo(struct flv_meta *mt, char *buf, size_t len)
{
	int i;
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

#if 0
void update_metainfo(struct flv_meta *mt, FILE *fp, size_t dlen)
{
	int i;
	size_t len;
	char *pmem = NULL;
	char buf[256 * 1024];
	double duration = 0.0;
	uint8_t duration_bytes[8];
	printf("dlen: %ld\n", dlen);
	assert(dlen < (256 * 1024));

	len = fread(buf, 1, dlen < sizeof(buf)? dlen: sizeof(buf), fp);
	if (len == 0)
		return;

	parse_metainfo(buf, len);

	pmem = (char *)xmemmem(buf, len, "duration", 8);
	if (pmem == NULL || pmem + 17l > buf + len) {
		printf("duration not found: %p %p %ld\n", pmem, buf + 142, len);
		return;
	}
	memcpy(&duration_bytes, pmem + 9l, 8);
	for (i = 0; i < 4; i ++) {
		uint8_t tmp = duration_bytes[i];
		duration_bytes[i] = duration_bytes[7 - i];
		duration_bytes[7 - i] = tmp;
	}
	memcpy(&duration, &duration_bytes, 8);
	combine->fc_duration += duration;
	if (combine->fc_flags & FLVF_SCRIPT)
		return;
	combine->fc_duration_offset = 
		combine->fc_filesize + (pmem + 9l - buf) + sizeof(struct taghdr);
	printf("duration offset: %d\n", combine->fc_duration_offset);
	pmem = (char *)xmemmem(buf, len, "filesize", 8);
	if (pmem == NULL || pmem + 17l - buf > len)
		return;
	combine->fc_filesize_offset = 
		combine->fc_filesize + (pmem + 9l - buf) + sizeof(struct taghdr);
}
#endif

int flv_load_meta(struct flv_meta *mt, const char *path)
{
	int error;
	FILE *flv_in;
	char magic[4];
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

	fprintf(stderr, "dlen %d\n", dlen);
	parse_metainfo(mt, d_buf, dlen);
	error = 0;

fail:
	fclose(flv_in);
	return error;
}

int addflv(struct flvcombine *combine, const char *path)
{
	int error = 0;
	FILE *fp, *fout;
	char magic[4];
	long savepos;
	size_t len, dlen, flags;
	struct flvhdr header;
	struct taghdr *last;
	struct taghdr tagvideo;
	struct taghdr tagaudio;
	struct taghdr tagheader;

	fp = fopen(path, "rb");
	fout = combine->fc_file;
	if (fp == NULL || fout == NULL)
		return 0;

	last = NULL;
	memset(magic, 0, sizeof(magic));
	memset(&tagvideo, 0, sizeof(tagvideo));
	memset(&tagaudio, 0, sizeof(tagaudio));

	if ( !fread(&header, sizeof(header), 1, fp) )
		goto fail;

	memcpy(magic, header.fh_magic, 3);
	if ( strcmp("FLV", magic) )
		goto fail;

	int remove_first_video_frame = (combine->fc_flags & FLVF_HEADER);
	if ((combine->fc_flags & FLVF_HEADER) == 0) {
		fwrite(&header, sizeof(header), 1, fout);
		combine->fc_filesize += sizeof(header);
		combine->fc_flags |= FLVF_HEADER;
	}

#if 0
	printf("magic: %s\n", magic);
	printf("flags: 0x%02x\n", header.fh_flags);
	printf("version: 0x%02x\n", header.fh_version);
	printf("header len: %d\n", buftoint(header.fh_hlen, sizeof(header.fh_hlen)));
#endif

	while (feof(fp) == 0) {
		int is_video_frame = 0;
		if ( !fread(&tagheader, sizeof(tagheader), 1, fp) )
			goto fail;

		dlen = buftoint(tagheader.th_dlen, sizeof(tagheader.th_dlen));

		switch (tagheader.th_type)
		{
			case 0x09:
				is_video_frame = 1;
				adjtimestamp(&tagheader, combine->fc_timestamp);
				tagvideo = tagheader;
				last = &tagvideo;
				break;

			case 0x08:
				adjtimestamp(&tagheader, combine->fc_timestamp);
				tagaudio = tagheader;
				last = &tagaudio;
				break;

			case 0x12:
				//update_metainfo(combine, fp, dlen);
				goto fail;

			default:
				//printf("type %x\n", tagheader.th_type);
				flags = combine->fc_flags;
				savepos = ftell(fp);
				if (savepos == -1)
					goto fail;
				savepos = (flags & FLVF_SCRIPT)? (savepos + dlen + 4): savepos;
				//update_metainfo(combine, fp, dlen);
				combine->fc_flags |= FLVF_SCRIPT;
				if ( fseek(fp, savepos, SEEK_SET) )
					goto fail;
				if (flags & FLVF_SCRIPT)
					continue;
				break;
		}
			
		savepos = ftell(fout);
		fwrite(&tagheader, sizeof(tagheader), 1, fout);
		combine->fc_filesize += sizeof(tagheader);
		combine->fc_filesize += (dlen + 4);
		if ( dd_copy(fout, fp, dlen + 4)) {
			break;
		}

		if (remove_first_video_frame && is_video_frame) {
			fseek(fout, savepos, SEEK_SET);
			remove_first_video_frame = 0;
		}
	}

fail:
	fclose(fp);
	if (last == &tagvideo || last == &tagaudio) {
		combine->fc_timestamp = buftoint(last->th_tstamp, sizeof(last->th_tstamp));
		combine->fc_timestamp |= (last->th_xstamp << 24);
		//printf("time stamp: %d\n", combine->fc_timestamp);
	}

	return 0;
}

void fixedflv(struct flvcombine *context)
{
	int i;
	double dblval = 0.0;
	uint8_t dblbytes[8];
	FILE *fout = context->fc_file;

	if (context->fc_filesize_offset > 0) {
		if ( fseek(fout, context->fc_filesize_offset, SEEK_SET) )
			return;
		dblval = context->fc_filesize;
		memcpy(dblbytes, &dblval, 8);

		for (i = 0; i < 4; i ++) {
			uint8_t tmp = dblbytes[i];
			dblbytes[i] = dblbytes[7 - i];
			dblbytes[7 - i] = tmp;
		}
		fwrite(dblbytes, 8, 1, fout);
		//printf("fix filesize\n");
	}

	if (context->fc_duration_offset > 0) {
		if ( fseek(fout, context->fc_duration_offset, SEEK_SET) )
			return;
		dblval = context->fc_duration;
		memcpy(dblbytes, &dblval, 8);

		for (i = 0; i < 4; i ++) {
			uint8_t tmp = dblbytes[i];
			dblbytes[i] = dblbytes[7 - i];
			dblbytes[7 - i] = tmp;
		}
		fwrite(dblbytes, 8, 1, fout);
		//printf("fix duration\n");
	}
}

static struct metatag *
flv_get_item(struct flv_meta *flv, const char *keyname)
{
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
		int cmp = strcmp(iter->title, keyname);
		if (cmp == 0)
			return iter;
		iter = iter->next;
	}

	return NULL;
}

static double
flv_get_value(struct flv_meta *flv, const char *keyname)
{
	struct metatag *tag;

	tag = flv_get_item(flv, keyname);
	if (tag == NULL || tag->tag != 0x00)
		return 0.0;
	return tag->dvalue;
}

static void
flv_set_value(struct flv_meta *flv, const char *keyname, double val)
{
	struct metatag *tag;
	tag = flv_get_item(flv, keyname);
	if (tag != NULL)
		tag->dvalue = val;
	return;
}

static double
flv_all_value(struct flv_meta *flv, const char *keyname)
{
	double val = 0.0;
	struct flv_meta *hi = NULL;

	for (hi = flv; hi; hi = hi->mt_next)
		val += flv_get_value(hi, keyname);

	return val;
}

int main(int argc, char *argv[])
{
	int i;
	struct metatag *tag;
	struct flv_meta *h0, *hi;
	struct flv_meta **tail = &h0;

	for (i = 1; i < argc; i++) {
		hi = (struct flv_meta *)malloc(sizeof(*hi));
		hi->mt_head = NULL;
		hi->mt_next = NULL;
		flv_load_meta(hi, argv[i]);
		*tail = hi;
		 tail = &hi->mt_next;
	}

	double duration  = flv_all_value(h0, "duration");
	double datasize  = flv_all_value(h0, "datasize");
	double filesize  = flv_all_value(h0, "filesize");
	double videosize  = flv_all_value(h0, "videosize");
	double audiosize  = flv_all_value(h0, "audiosize");

	flv_set_value(h0, "duration", duration);
	flv_set_value(h0, "datasize", datasize);
	flv_set_value(h0, "filesize", filesize);
	flv_set_value(h0, "videosize", videosize);
	flv_set_value(h0, "audiosize", audiosize);

	struct metatag * mm_times = NULL;
	struct metatag * mm_filepositions = NULL;

	for (hi = h0; hi != NULL; hi = hi->mt_next) {
		tag = flv_get_item(hi, "keyframes");
#if 0
		printf("keyframes: %p\n", tag);
		printf("tagdata: %p\n", tag->tagdata);
		printf("tag: %p\n", tag->tagdata->tag);
#endif

		for (tag = tag->tagdata;
				tag != NULL; tag = tag->next) {
			if (tag->tag != 0x0A) {
				//printf("unsupported tag: %x\n", tag->tag);
				continue;
			}

			if (strcmp(tag->title, "filepositions") == 0) {
				if (tag->tagdata != NULL) {
					if (mm_filepositions != NULL)
						mm_filepositions->next = tag->tagdata;
					mm_filepositions = tag->tagdata;
					while (mm_filepositions->next != NULL)
						mm_filepositions = mm_filepositions->next;
				}
			} else if (strcmp(tag->title, "times") == 0) {
				if (tag->tagdata != NULL) {
					if (mm_times != NULL)
						mm_times->next = tag->tagdata;
					mm_times = tag->tagdata;
					while (mm_times->next != NULL)
						mm_times = mm_times->next;
				}
			}
		}
	}

#if 1
	{
		struct metatag *tag = h0->mt_head;
		while (tag != NULL) {
			write_tag_object(tag);
			tag = tag->next;
		}
		//printf("\n");
	}
#endif

#if 0
	memset(&context, 0, sizeof(context));
	context.fc_file = fopen("out.flv", "wb");
	if (context.fc_file == NULL)
		return -1;
	context.fc_duration = 0;
	for (i = 1; i < argc; i++)
		addflv(&context, argv[i]);
	fixedflv(&context);
	fclose(context.fc_file);
	printf("seconds: %d\n", context.fc_timestamp);
#endif
	return 0;
}
