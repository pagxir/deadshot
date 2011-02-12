#include <stdio.h>
#include <windows.h>

/* OPTION:
 * bs=BYTES
 * 		force ibs=BYTES and obs = BYTES
 * count=BLOCKS
 * 		copy only BLOCKS input blocks
 * ibs=BYTES
 * 		read BYTES bytes at a time
 * if=FILE
 *		read from FILE instead of stdin
 * obs=BYTES
 * 		write BYTES bytes at a time
 * of=FILE
 * 		write to FILE instead of stdout
 * seek=BLOCKS
 * 		skip BLOCKS obs-sized blocks at start of output
 * skip=BLOCKS
 * 		skip BLOCKS ibs-sized blocks at start of input
 * BLOCKS and BYTES may be followed by the following multiplicative suffixes:
 * xM M, c 1, w 2, b 512, kB 1000, K 1024, MB 1000 * 1000, M 1024 * 1024, 
 * GB 1000 * 1000 * 1000, G 1024 * 1024 * 1024, and so on for T, P, E, Z, Y.
 */

#define ARG_INT(p, m, s) \
	if ( !strncmp(argline, s, strlen(s)) ) { \
		illegal_argument(s, flags & m); \
		*(p) = intconvert(optvalue, s); \
		flags |= m; \
		continue; \
	}

#define ARG_STRING(p, m, s) \
	if ( !strncmp(argline, s, strlen(s)) ) { \
		illegal_argument(s, flags & m); \
		*(p) = optvalue; \
		flags |= m; \
		continue; \
	}

static char * getoptvalue(char * line)
{
   	char * pequal = strchr(line, '=');

   	if (pequal == NULL) {
	   	fprintf(stderr, "unkown operand %s", line);
	   	exit(-1);
   	}

	if (pequal[1] == 0) {
	   	fprintf(stderr, "no value specified for %s", pequal);
		exit(-1);
	}

	return &pequal[1];
}

static void illegal_number(const char * str, int flags)
{
	char * dp;
	char name[256];

	if (flags) {
		strncpy(name, str, sizeof(name));
		name[sizeof(name) - 1] = 0;
		if (!(dp = strchr(name, '=')))
			name[dp - name] = 0;
		fprintf(stderr, "%s: illegal numberic value", name);
		exit(-1);
	}

	return;
}

static int intconvert(const char * str, const char * msg)
{
	int num = 0;
	int flags = 0;

	const char * orig = str;
	while (*str && isdigit(*str))
	   	num = num * 10 + (*str++ - '0');

	if (orig == str) {
		fprintf(stderr, "%s: Invalid argument", msg);
		exit(-1);
	}

#define SUFFIXES(s, f) \
	if (!strcmp(s, str)) { \
		illegal_number(msg, flags); \
		num *= (f); \
	   	flags = 1;  \
	}

	SUFFIXES("xM", 1024 * 1024);
	SUFFIXES("c", 1);
	SUFFIXES("w", 2);
	SUFFIXES("b", 512);
	SUFFIXES("kB", 1000);
	SUFFIXES("K", 1024);
	SUFFIXES("MB", 1000 * 1000);
	SUFFIXES("M", 1024 * 1024);
	SUFFIXES("GB", 1000 * 1000 * 1000);
	SUFFIXES("G", 1024 * 1024 * 1024);
#undef SUFFIXES

	if (flags == 0 && *str != 0) {
		fprintf(stderr, "%s: Invalid argument", msg);
		exit(-1);
	}

	return num;
}

static void illegal_argument(const char * str, int flags)
{
	char * dp;
	char name[256];
	const char * title = "illegal argument combination or already set";

	if (flags) {
		strncpy(name, str, sizeof(name));
		name[sizeof(name) - 1] = 0;
		if (!(dp = strchr(name, '=')))
			name[dp - name] = 0;
		fprintf(stderr, "%s: %s\n", name, title);
		exit(-1);
	}

	return;
}

static void valid_size(const char * str, int val)
{
	if (val == 0) {
		fprintf(stderr, "%s: invalid size", str);
		exit(-1);
	}

	return;
}

static void valid_buffer(const char * str, void * pointer)
{
	if (pointer == NULL) {
		fprintf(stderr, "%s: invalid size", str);
		exit(-1);
	}

	return;
}

static void valid_handle(const char * str, HANDLE handle)
{
	if (handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "%s: invalid handle\n", str);
		exit(-1);
	}

	return;
}

#define FILE_FLAGS (FILE_SHARE_READ | FILE_SHARE_WRITE)

static HANDLE open_file(const char * path, int mode)
{
	HANDLE handle;

	if (!strcmp(path, "-") && mode == GENERIC_READ)
	   	return GetStdHandle(STD_INPUT_HANDLE);

	if (!strcmp(path, "-") && mode == GENERIC_WRITE)
	   	return GetStdHandle(STD_OUTPUT_HANDLE);

	handle = CreateFile(path, mode, FILE_FLAGS, 0, OPEN_EXISTING, 0, 0);

	if (mode == GENERIC_WRITE &&
			handle == INVALID_HANDLE_VALUE &&
			GetLastError() == ERROR_FILE_NOT_FOUND)
	   	return CreateFile(path, mode, FILE_FLAGS, 0, CREATE_NEW, 0, 0);

	return handle;
}

void symlink_remove(const char * symbol, const char * target)
{
	const DWORD flags = DDD_REMOVE_DEFINITION;// | DDD_EXACT_MATCH_ON_REMOVE;

	if (strncmp(symbol, "\\\\.\\", 4) == 0 &&
		   	!DefineDosDevice(flags, symbol + 4, NULL)) {
		fprintf(stderr, "remove symlink fail: %s -> %s, err = %d\n", 
				symbol, target, GetLastError());
	   	exit(-1);
	}

	fprintf(stderr, "symlink_remove: %s -> %s\n", symbol, target);
	return;
}

void symlink_create(const char * symbol, const char * target)
{
	const DWORD flags = DDD_RAW_TARGET_PATH;

	if (strncmp(symbol, "\\\\.\\", 4) == 0 &&
		   	!DefineDosDevice(flags, symbol + 4, target)) {
		fprintf(stderr, "remove symlink fail: %s -> %s, err = %d\n", 
				symbol, target, GetLastError());
	   	exit(-1);
	}

	fprintf(stderr, "symlink_create: %s -> %s\n", symbol, target);
	return;
}

int main(int argc, char * argv[])
{
	int i;
	int read_write_error;
	int input_stat[2] = {0};
	int output_stat[2] = {0};

	int flags = 0;
	int count = -1;
	int skip = 0, seek = 0;
	int bs = -1, ibs = 4096, obs = 4096;
	int buffer_size = 0;
	int count_read, count_write;
	DWORD time_start, time_finish, time_use;

	const char * input_path = "-";
	const char * output_path = "-";
	const char * input_device = NULL;
	const char * output_device = NULL;

	HANDLE input_handle, output_handle;
	char * buffer_read, * buffer_write, * buffer_alloc;

	for (i = 1; i < argc; i++) {
		char * argline = argv[i];
		char * optvalue = getoptvalue(argv[i]);

		ARG_INT(&ibs, 1, "ibs=");
		ARG_INT(&obs, 2, "obs=");
		ARG_INT(&bs, (1 | 2), "bs=");
		ARG_INT(&seek, 4, "seek=");
		ARG_INT(&skip, 8, "skip=");
		ARG_INT(&count, 16, "count=");
		ARG_STRING(&input_path, 32, "if=");
		ARG_STRING(&output_path, 64, "of=");
		ARG_STRING(&input_device, 128, "kin=");
		ARG_STRING(&output_device, 256, "kout=");

	   	fprintf(stderr, "unkown operand %s", argline);
		exit(-1);
	}

	if (bs != -1) {
		ibs = bs;
		obs = bs;
	}

	valid_size("invalid input block size", ibs);
	valid_size("invalid output block size", obs);

	input_handle = open_file(input_path, GENERIC_READ);
	if (input_device != NULL &&
			input_handle == INVALID_HANDLE_VALUE) {
		symlink_create(input_path, input_device);
	   	input_handle = open_file(input_path, GENERIC_READ);
	}
	valid_handle("invalid input handle", input_handle);

	output_handle = open_file(output_path, GENERIC_WRITE);
	if (output_device != NULL &&
			output_handle == INVALID_HANDLE_VALUE) {
		symlink_create(output_path, output_device);
	   	output_handle = open_file(output_path, GENERIC_WRITE);
	}
	valid_handle("invalid output handle", output_handle);

	buffer_size = (ibs < obs? obs: ibs) * 2;
	buffer_alloc = (char *)malloc(buffer_size);
	valid_buffer("alloc buffer fail", buffer_alloc);

	if (seek > 0) {
		DWORD pos = SetFilePointer(output_handle,
			   	seek * obs, NULL, FILE_CURRENT);
	   	valid_size("seek ouput file fail", pos != INVALID_SET_FILE_POINTER);
		valid_size("seek output file fail", pos == seek * obs);
	}

	if (skip > 0) {
		DWORD pos = SetFilePointer(input_handle,
			   	skip * ibs, NULL, FILE_CURRENT);
	   	valid_size("skip input file fail", pos != INVALID_SET_FILE_POINTER);
		valid_size("skip input file fail", pos == skip * ibs);
   	}

	read_write_error = 0;
	count_read = count_write = 0;
	buffer_read = buffer_write = buffer_alloc;

	time_start = GetTickCount();
	while (read_write_error == 0) {
		DWORD transfer = 0;

		while (buffer_read < buffer_alloc + obs) {
			if (!ReadFile(input_handle, buffer_read, ibs, &transfer, NULL)) {
				read_write_error = 2;
				break;
			}

			if (transfer == 0) {
				read_write_error = 1;
				break;
			}

			buffer_read += transfer;
			count_read += transfer;

			input_stat[transfer == ibs]++;
			if (input_stat[0] + input_stat[1] == count) {
				read_write_error = 1;
				break;
			}
		}

		while (buffer_write + obs <= buffer_read) {
			if (!WriteFile(output_handle, buffer_write, obs, &transfer, NULL)) {
				read_write_error = 2;
				break;
			}

			if (transfer == 0) {
				read_write_error = 2;
				break;
			}

			output_stat[transfer == obs]++;
			buffer_write += transfer;
			count_write += transfer;
		}

		memmove(buffer_alloc, buffer_write, count_read - count_write);
		buffer_read = buffer_alloc + (count_read - count_write);
		buffer_write = buffer_alloc;
	}

	while (read_write_error == 1 &&
			count_write < count_read) {
		DWORD transfer = (count_read - count_write);

		valid_size("internal error", transfer < obs);
		if (WriteFile(output_handle, buffer_write, transfer, &transfer, NULL)) {
		   	output_stat[transfer == obs]++;
		   	buffer_write += transfer;
		   	count_write += transfer;
			continue;
		}

		if (WriteFile(output_handle, buffer_write, obs, &transfer, NULL)) {
		   	output_stat[transfer == obs]++;
		   	buffer_write += transfer;
		   	count_write += transfer;
			continue;
		}
	   
		read_write_error = 3;
		break;
	}
	time_finish = GetTickCount();

	CloseHandle(output_handle);
	CloseHandle(input_handle);
	free(buffer_alloc);

	if (input_device != NULL)
		symlink_remove(input_path, input_device);

	if (output_device != NULL)
		symlink_remove(output_path, output_device);

	time_use = time_finish > time_start? time_finish - time_start: 1;
	fprintf(stderr, "%d+%d records in\n", input_stat[1], input_stat[0]);
	fprintf(stderr, "%d+%d records out\n", output_stat[1], output_stat[0]);
	fprintf(stderr, "%d bytes transferred in %f secs (%.0f bytes/sec)\n",
		   	count_read, time_use / 1000.0, count_read * 1000.0 / time_use);
	return 0;
}

