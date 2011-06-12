#include <stdio.h>
#include <assert.h>
#include <winsock2.h>

#include "cantainer.h"

#define SF_FIRSTFILE 1
#define SF_CACULATED 2
#define SF_COLLECTED 4
#define SF_COMPLETED 8

struct prefix {
	long size;
	char magic[4];
};

static char *cantainers[] = {
	"moov", "trak", "mdia", "minf",
   	"dinf", "stbl", NULL 
};

static char *st_chunks[] = {
	"stsd", "stts", "stsc", "stsz",
	"stco", "stss", "ctts", NULL
};

enum {STSD, STTS, STSC, STSZ, STCO, STSS, CTTS, ST_MAX};

struct mp4_box_info {
	struct mp4_box_info *bi_head;
	struct mp4_box_info *bi_next;

	int bi_type;
	int bi_length;
	long bi_small[2];
	char *bi_buffer;
};

struct mp4_trak_info {
	int ti_flags;
	int ti_nalign[ST_MAX];
	int ti_nlength[ST_MAX];
	int ti_ncounter[ST_MAX];
	struct mp4_box_info *ti_stboxs[ST_MAX];

	int ti_duration_tkhd;
	int *ti_duration_tkhdp;
	int ti_duration_mdhd;
	int *ti_duration_mdhdp;
};

struct mp4_merg_info {
	int mi_nitem;
	int mi_nbytes;
	int mi_nitem2;
	int mi_duration_tkhd;
	int mi_duration_mdhd;

	char *mi_base;
	char *mi_buff;
};

struct mp4_file_info {
	int fi_flags;
	int fi_mdato;
	int fi_mdats;
	int fi_trako;
	int fi_level;

	char **fi_cantainers;
	struct mp4_trak_info fi_traks[10];

	struct mp4_box_info *fi_mdatp;
	struct mp4_box_info *fi_header;
	struct mp4_box_info **fi_tailer;

	int fi_duration;
	int *fi_durationp;
};

struct mp4_mvhd_info {
	int mi_size;
	int mi_type; //mvhd
	char mi_version;
	char mi_flags[3];
	int mi_create_time;
	int mi_modificate_time;
	int mi_time_scale;
	int mi_duration; // time duration
	int mi_rate;
	char mi_volume[2];
	char mi_reserved[10];
	char mi_matrix[36];
	char mi_pre_defined[24];
	int mi_next_trackid;
};

struct mp4_tkhd_info {
	int mi_size;
	int mi_type;
	char mi_version;
	char mi_flags[3];
	int mi_create_time;
	int mi_modificate_time;
	int mi_trackid;
	int mi_reserved;
	int mi_duration; //time duration
	int mi_reserved1[2];
	short mi_layer;
	short mi_alernate_group;
	short mi_volume;
	short mi_reserved2;
	char mi_matrix[36];
	int mi_width;
	int mi_height;
};

struct mp4_mdhd_info {
	int mi_size;
	int mi_type;
	char mi_version;
	char mi_flags[3];
	int mi_create_time;
	int mi_modificate_time;
	int mi_time_scale;
	int mi_duration; // duration time
	char mi_language[2];
	char mi_pre_defined[2];
};

static int
mp4_typeof(const char *objtyp, const char *mp4typ)
{
	if (objtyp != NULL)
		return !memcmp(objtyp, mp4typ, 4);
	return 0;
}

static void
mp4_box_free(struct mp4_box_info *boxp)
{
	if (boxp != NULL) {
		if (boxp->bi_head)
			mp4_box_free(boxp->bi_head);
	   	if (boxp->bi_next)
		   	mp4_box_free(boxp->bi_next);
		free(boxp);
	}
}

static struct mp4_box_info *
mp4_box_copy(struct mp4_file_info *fip,
		struct cantainer *canp, struct prefix *pfixp)
{
	struct prefix *pfixp1; 
   	struct mp4_box_info *boxp;

	boxp = (struct mp4_box_info *)
		malloc(sizeof(*boxp) + pfixp->size);
	boxp->bi_buffer = (char *)(boxp + 1);
	boxp->bi_length = pfixp->size;
	boxp->bi_head = 0;
	boxp->bi_next = 0;
	boxp->bi_type = 0;

	pfixp1 = (struct prefix *)(boxp + 1);
	memcpy(pfixp1, pfixp, sizeof(*pfixp1));
	pfixp1->size = ntohl(pfixp1->size);
	cantainer_read(canp, boxp->bi_buffer + sizeof(*pfixp), pfixp->size - 8);

	*fip->fi_tailer = boxp;
	fip->fi_tailer = &boxp->bi_next;
	return boxp;
}

static void
mp4_table_load(struct mp4_file_info *fip,
	   	struct cantainer *canp, struct prefix *pfixp, int index)
{
	int fmask;
	long *valuep;
	struct mp4_box_info *boxp;
	struct mp4_trak_info *trakp;

	fmask = (1 << index);
	trakp = (struct mp4_trak_info *)&fip->fi_traks[fip->fi_trako];
	assert((trakp->ti_flags & fmask) == 0);

	boxp = mp4_box_copy(fip, canp, pfixp);
	trakp->ti_stboxs[index] = boxp;
	trakp->ti_flags |= fmask;

	switch (index) {
		case STTS:
		case STSC:
			valuep = (long *)boxp->bi_buffer;
			assert(valuep[2] == 0);
			trakp->ti_nalign[index] = 16;
			trakp->ti_ncounter[index] = ntohl(valuep[3]);
		   	trakp->ti_nlength[index] = (pfixp->size - 16);
			break;

		case STSZ:
			valuep = (long *)boxp->bi_buffer;
			assert(valuep[2] == 0);
			trakp->ti_nalign[index] = 20;
			trakp->ti_ncounter[index] = ntohl(valuep[4]);
		   	trakp->ti_nlength[index] = (pfixp->size - 20);
			break;

		case STCO:
		case STSS:
		case CTTS:
			valuep = (long *)boxp->bi_buffer;
			assert(valuep[2] == 0);
			trakp->ti_nalign[index] = 16;
			trakp->ti_ncounter[index] = ntohl(valuep[3]);
		   	trakp->ti_nlength[index] = (pfixp->size - 16);
			break;

		default:
			valuep = (long *)boxp->bi_buffer;
			assert(valuep[2] == 0);
			trakp->ti_nalign[index] = 16;
			trakp->ti_ncounter[index] = ntohl(valuep[3]);
		   	trakp->ti_nlength[index] = (pfixp->size - 16);
			break;
	}
}

static void
mp4_file_init(struct mp4_file_info *fip)
{
	fip->fi_flags = 0;
	fip->fi_mdato = 0;
	fip->fi_trako = 0;
	fip->fi_level = 0;
	fip->fi_mdatp = 0;
	fip->fi_header = 0;

	fip->fi_tailer = &fip->fi_header;
	fip->fi_cantainers = cantainers;
	memset(fip->fi_traks, 0, sizeof(fip->fi_traks));
}

static void
mp4_file_fini(struct mp4_file_info *fip)
{
	fip->fi_flags = 0;
	fip->fi_mdato = 0;
	fip->fi_trako = 0;
	fip->fi_level = 0;
	fip->fi_header = 0;
	mp4_box_free(fip->fi_header);
}

static struct mp4_box_info **
mp4_can_new(struct mp4_file_info *fip, const char *magic)
{
	struct mp4_box_info *boxp;
   
	boxp = (struct mp4_box_info *)malloc(sizeof(*boxp));
	memcpy(&boxp->bi_small[1], magic, 4);
	boxp->bi_buffer = 0;
	boxp->bi_length = 0;
	boxp->bi_head = 0;
	boxp->bi_next = 0;
	boxp->bi_type = 2;

	*fip->fi_tailer = boxp;
	fip->fi_tailer = &boxp->bi_head;
	return &boxp->bi_next;
}

static size_t
mp4_box_size(struct mp4_box_info *boxp)
{
	int size;

	assert(boxp != NULL);
	switch (boxp->bi_type) {
		case 0:
		case 1:
			size = boxp->bi_length;
			break;

		case 2:
			size = 8;
			for (boxp = boxp->bi_head;
				   	boxp; boxp = boxp->bi_next)
				size += mp4_box_size(boxp);
			break;

		default:
			assert(0);
			break;
	}

	return size;
}

static size_t
mp4_box_update(struct mp4_box_info *boxp)
{
	int size;
	int count;

	size = 0;
	while (boxp != NULL) {
		switch (boxp->bi_type) {
			case 0:
			case 1:
				count = boxp->bi_length;
				break;

			case 2:
				count = mp4_box_update(boxp->bi_head) + 8;
				boxp->bi_small[0] = htonl(count);
				boxp->bi_length = (count);
				break;

			default:
				assert(0);
				break;
		}

		boxp = boxp->bi_next;
		size += count;
	}

	return size;
}

static size_t
mp4_head_size(struct mp4_file_info *fip)
{
	size_t count;
	struct mp4_box_info *boxp;

	count = 0;
	for (boxp = fip->fi_header;
			boxp != NULL; boxp = boxp->bi_next) {
		if (boxp == fip->fi_mdatp)
			break;
		count += mp4_box_size(boxp);
	}

	return count;
}

static void
mp4_file_parse(struct mp4_file_info *fip, struct cantainer *canp)
{
   	int i;
	int level;
	int offset;
	char **cans_list;
	struct prefix pfix;
	struct cantainer *canp1;
	struct mp4_box_info **boxpp;

	level = fip->fi_level++;
	cans_list = fip->fi_cantainers;

	offset = 0;
	for ( ; ; ) {
	   	int done;
	   	int error;

		error = cantainer_read(canp, &pfix, sizeof(pfix));
		if (error < sizeof(pfix))
			break;

		pfix.size = ntohl(pfix.size);
		fprintf(stderr, "%*.4s\n", level * 4, pfix.magic);

		if (pfix.size < 8)
			goto finally;

		done = 0;
		canp1 = cantainer_box(canp, pfix.size);
		for (i = 0; cans_list[i]; i++) {
			if (!memcmp(cans_list[i], pfix.magic, 4)) {
				fip->fi_cantainers = (cans_list + i + 1);
				boxpp = mp4_can_new(fip, cans_list[i]);
				mp4_file_parse(fip, canp1);
				fip->fi_tailer = boxpp;
				done = 1;
				break;
			}
		}

		for (i = 0; st_chunks[i] && !cans_list[0]; i++) {
			if (!memcmp(st_chunks[i], pfix.magic, 4)) {
				mp4_table_load(fip, canp1, &pfix, i); 
				done = 1;
				break;
			}
	   	}

		if (!done) {
			struct mp4_box_info *boxp;
		   	if (!memcmp("mdat", pfix.magic, 4)) {
				fip->fi_mdats = pfix.size;
				fip->fi_mdato += offset;
				pfix.size = 8;
			}

			boxp = mp4_box_copy(fip, canp1, &pfix);
		   	if (!memcmp("mdat", pfix.magic, 4)) {
				assert(fip->fi_mdatp == NULL);
			   	fip->fi_mdatp = boxp;
			}

			if (!memcmp("mvhd", pfix.magic, 4)) {
				struct mp4_mvhd_info *mip;
				mip = (struct mp4_mvhd_info *)boxp->bi_buffer;
				fip->fi_duration = htonl(mip->mi_duration);
				fip->fi_durationp = &mip->mi_duration;
			}

			if (!memcmp("tkhd", pfix.magic, 4)) {
				struct mp4_tkhd_info *tip;
				struct mp4_trak_info *trakp;
				tip = (struct mp4_tkhd_info *)boxp->bi_buffer;
			   	trakp = (struct mp4_trak_info *)&fip->fi_traks[fip->fi_trako];
				trakp->ti_duration_tkhd = htonl(tip->mi_duration);
				trakp->ti_duration_tkhdp = &tip->mi_duration;
			}

			if (!memcmp("mdhd", pfix.magic, 4)) {
				struct mp4_mdhd_info *mip;
				struct mp4_trak_info *trakp;
				mip = (struct mp4_mdhd_info *)boxp->bi_buffer;
			   	trakp = (struct mp4_trak_info *)&fip->fi_traks[fip->fi_trako];
				trakp->ti_duration_mdhd = htonl(mip->mi_duration);
				trakp->ti_duration_mdhdp = &mip->mi_duration;
			}
		}

		cantainer_close(canp1);
		offset += pfix.size;
	}

finally:
	if (mp4_typeof(*cans_list, "mdia")) {
		assert(fip->fi_trako < 9);
		fip->fi_trako++;
	}
	fip->fi_cantainers = cantainers;
	fip->fi_level = level;
}

static void
mp4_merge_trak1(struct mp4_merg_info *mip, struct mp4_trak_info *tip)
{
	int i;

	for (i = 0; i < ST_MAX; i++) {
		mip[i].mi_duration_tkhd += tip->ti_duration_tkhd;
		mip[i].mi_duration_mdhd += tip->ti_duration_mdhd;
	   	mip[i].mi_nitem += tip->ti_ncounter[i];
	   	mip[i].mi_nbytes += tip->ti_nlength[i];
	}
}

static void
mp4_merge_trak2(struct mp4_merg_info *mip,
	   	struct mp4_trak_info *tip, int adjval)
{
	int i, j;
	long *srcp, *dstp;
	struct mp4_box_info *boxp;

	for (i = 0; i < ST_MAX; i++) {
	   	boxp = tip->ti_stboxs[i];

		if (tip->ti_flags & (1 << i)) {
			assert(boxp != NULL);
			assert(boxp->bi_length > 16);
			assert(boxp->bi_buffer != NULL);

			switch(i) {
				case STSD:
					dstp = (long *)mip[i].mi_base;
					srcp = (long *)boxp->bi_buffer;
					assert(boxp->bi_length == mip[i].mi_nbytes);
					assert(!memcmp(dstp, srcp, mip[i].mi_nbytes));
					break;

				case STCO:
				   	dstp = (long *)mip[i].mi_buff;
					srcp = (long *)(boxp->bi_buffer + tip->ti_nalign[i]);
					for (j = 0; j < tip->ti_ncounter[i]; j++) {
						*dstp++ = htonl(ntohl(srcp[j]) + adjval);
						mip[i].mi_buff += 4;
					}
					break;

				case STSS:
					dstp = (long *)mip[i].mi_buff;
					srcp = (long *)(boxp->bi_buffer + tip->ti_nalign[i]);
					for (j = 0; j < tip->ti_ncounter[i]; j++) {
						if (mip[STSZ].mi_nitem2 != 0) {
						   	*dstp++ = htonl(ntohl(srcp[j]) + mip[STSZ].mi_nitem2);
						   	mip[i].mi_buff += 4;
							continue;
						}
						mip[i].mi_buff += 4;
					   	*dstp++ = (srcp[j]);
					}
					break;

				case STSC:
					dstp = (long *)mip[i].mi_buff;
					srcp = (long *)(boxp->bi_buffer + tip->ti_nalign[i]);
					for (j = 0; j < tip->ti_ncounter[i] * 3; j++) {
						if ((j % 3) == 0 && mip[STCO].mi_nitem2) {
						   	*dstp++ = htonl(ntohl(srcp[j]) + mip[STCO].mi_nitem2);
						   	mip[i].mi_buff += 4;
							continue;
						}
						mip[i].mi_buff += 4;
						*dstp++ = srcp[j];
					}
					break;

				case STTS:
				case CTTS:
				default:
					dstp = (long *)mip[i].mi_buff;
					srcp = (long *)(boxp->bi_buffer + tip->ti_nalign[i]);
					memcpy(dstp, srcp, tip->ti_nlength[i]);
					mip[i].mi_buff += tip->ti_nlength[i];
					break;
			}
		}
	}

	mip[STSZ].mi_nitem2 += tip->ti_ncounter[STSZ];
	mip[STCO].mi_nitem2 += tip->ti_ncounter[STCO];
}

static int
mp4_box_output(struct mp4_box_info *boxp, FILE *mp4fp)
{
   	int size;

	assert(boxp != NULL);
	switch (boxp->bi_type) {
		case 0:
		case 1:
			size = boxp->bi_length;
		   	fwrite(boxp->bi_buffer, size, 1, mp4fp);
			break;

		case 2:
		   	fwrite(boxp->bi_small, 8, 1, mp4fp);
		   	for (boxp = boxp->bi_head;
				   	boxp; boxp = boxp->bi_next)
				size += mp4_box_output(boxp, mp4fp);
			break;

		default:
			assert(0);
			break;
	}

	return size;
}

static void
file_copy(FILE *dfp, FILE *sfp, size_t count, size_t offset)
{
	int len;
	int error;
	char buf[1024 * 64];

	fseek(sfp, offset, SEEK_SET);
	while (!feof(sfp) && count >= sizeof(buf)) {
		len = fread(buf, 1, sizeof(buf), sfp);
		if (len <= 0)
			continue;
	   	error = fwrite(buf, 1, len, dfp);
		assert(error == len);
	   	count -= len;
	}

	while (!feof(sfp) && count > 0) {
		len = fread(buf, 1, sizeof(buf), sfp);
		if (len <= 0)
			continue;
	   	error = fwrite(buf, 1, len, dfp);
		assert(error == len);
	   	count -= len;
	}

	while (count >= sizeof(buf)) {
		error = fwrite(buf, 1, sizeof(buf), dfp);
		assert(error == sizeof(buf));
		count -= error;
	}

	if (count > 0) {
		error = fwrite(buf, 1, count, dfp);
		assert(error == count);
	}
}

static void
mp4_file_merge(size_t count, struct mp4_file_info *fips, char *paths[])
{
	int i, j;
	int ntrak;
	int adjoff;
	int mdatoff;
	int mdatsiz;
	int moovlen;
	long sthd[4];
	int trak_flags[10];
	struct mp4_file_info *fip;
	struct mp4_box_info *boxp;
   	struct mp4_trak_info *tip;
   	struct mp4_merg_info *mip;
	struct mp4_merg_info mergs[10][ST_MAX];

	moovlen = 0;
	memset(mergs, 0, sizeof(mergs));
	for (i = 0; i < count; i++) {
		fip = fips + i;
		ntrak = fip->fi_trako;
		moovlen += fip->fi_duration;
		for (j = 0; j < ntrak; j++) {
		   	trak_flags[j] = fip->fi_traks[j].ti_flags;
			mp4_merge_trak1(mergs[j], fip->fi_traks + j);
		}
	}

	if (count > 0) {
		int trak_size = 0;
		int merg_size = 0;

		fip = fips;
		assert(fip->fi_trako == ntrak);
		for (j = 0; j < ntrak; j++) {
			mip = mergs[j];
			tip = fip->fi_traks + j;
			assert(trak_flags[j] == tip->ti_flags);

			for (i = 1; i < ST_MAX; i++) {
			   	boxp = tip->ti_stboxs[i];
			   	if (tip->ti_flags & (1 << i)) {
					int align = tip->ti_nalign[i];
					trak_size += boxp->bi_length;
					mip[i].mi_nbytes += align;
					merg_size += (mip[i].mi_nbytes);
					mip[i].mi_base = (char *)malloc(mip[i].mi_nbytes);
					mip[i].mi_buff = (mip[i].mi_base + align);
				}
			}

		   	boxp = tip->ti_stboxs[STSD];
			if (tip->ti_flags & (1 << STSD)) {
			   	trak_size += boxp->bi_length;
				merg_size += boxp->bi_length;
				mip[STSD].mi_nbytes /= count;
				mip[STSD].mi_nbytes += 16;
				assert(boxp->bi_length == mip[STSD].mi_nbytes);
			   	mip[STSD].mi_base = (char *)malloc(boxp->bi_length);
			   	mip[STSD].mi_buff = (mip[STSD].mi_base + 16);
				memcpy(mip[STSD].mi_base, boxp->bi_buffer, boxp->bi_length);
		   	}
		}

		mdatoff = mp4_head_size(fip) + merg_size - trak_size;
		mdatsiz = 0;
	}

	for (i = 0; i < count; i++) {
		fip = fips + i;
		assert(fip->fi_trako == ntrak);
	   	adjoff = mdatoff - fip->fi_mdato;
		for (j = 0; j < ntrak; j++) {
			assert(trak_flags[j] == fip->fi_traks[j].ti_flags);
			mp4_merge_trak2(mergs[j], fip->fi_traks + j, adjoff);
		}
		mdatsiz += (fip->fi_mdats - 8);
		mdatoff += (fip->fi_mdats - 8);
	}

	if (count > 0) {
		long *valup;

		fip = fips;
		*fip->fi_durationp = htonl(moovlen);

		for (j = 0; j < ntrak; j++) {
			mip = mergs[j];
			tip = fip->fi_traks + j;

			*tip->ti_duration_tkhdp = htonl(mip->mi_duration_tkhd);
			*tip->ti_duration_mdhdp = htonl(mip->mi_duration_mdhd);

			for (i = 1; i < ST_MAX; i++) {
			   	boxp = tip->ti_stboxs[i];
			   	if (tip->ti_flags & (1 << i)) {
					valup = (long *)mip[i].mi_base;
					valup[0] = ntohl(mip[i].mi_nbytes);
					memcpy(valup + 1, st_chunks[i], 4);
					valup[2] = 0;
				   	valup[3 + (i == STSZ)] = htonl(mip[i].mi_nitem);
					boxp->bi_buffer = mip[i].mi_base;
					boxp->bi_length = mip[i].mi_nbytes;
				}
			}
		}

		mp4_box_update(fip->fi_header);

		FILE *mp4fp = fopen("output.mp_", "wb");
		if (mp4fp != NULL) {
		   	struct prefix pfix;

			boxp = fip->fi_header;
			assert(fip->fi_mdatp != NULL);
			while (boxp != NULL) {
				if (boxp != fip->fi_mdatp) {
				   	mp4_box_output(boxp, mp4fp);
				   	boxp = boxp->bi_next;
					continue;
				}

				memcpy(pfix.magic, "mdat", 4);
				pfix.size = htonl(mdatsiz + 8);
				fwrite(&pfix, 1, 8, mp4fp);

				for (i = 0; i < count; i++) {
					FILE *filp = fopen(paths[i], "rb");
					assert(filp != NULL);
					size_t count = fips[i].fi_mdats - 8;
					size_t offset = fips[i].fi_mdato + 8;
					fprintf(stderr, "%d\n", offset);
					file_copy(mp4fp, filp, count, offset);
					fclose(filp);
				}
				boxp = boxp->bi_next;
			}
			fclose(mp4fp);
		}
	}
}

static void
mp4_file_load(struct mp4_file_info *fip, const char *path)
{
	int error;
	struct prefix pfix;
	struct cantainer *canp;
	struct cantainer *canp1;

	mp4_file_init(fip);
	canp = cantainer_file(path);
	error = cantainer_read(canp, &pfix, sizeof(pfix));
	if (error < sizeof(pfix))
		goto finally;

	pfix.size = ntohl(pfix.size);
	if (pfix.size < 8 ||
		   	memcmp(pfix.magic, "ftyp", 4))
		goto finally;

	canp1 = cantainer_box(canp, pfix.size);
	mp4_box_copy(fip, canp1, &pfix);
	cantainer_close(canp1);

	fip->fi_mdato = pfix.size;
	mp4_file_parse(fip, canp);

finally:
	cantainer_close(canp);
}

int main(int argc, char *argv[])
{
	int i;
	struct mp4_file_info *fips;

	fips = (struct mp4_file_info *)
	   	malloc(sizeof(struct mp4_file_info) * argc);

	for (i = 1; i < argc; i++)
		mp4_file_load(fips + i, argv[i]);

	mp4_file_merge(argc - 1, fips + 1, argv + 1);

	for (i = 1; i < argc; i++)
		mp4_file_fini(fips + i);

	free(fips);
	return 0;
}

