/* hid_gadget_test */

#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#define BUF_LEN 512

struct options {
	const char    *opt;
	unsigned char val;
};

static struct options kmod[] = {
	{.opt = "left-ctrl",		.val = 0x01},
	{.opt = "right-ctrl",		.val = 0x10},
	{.opt = "left-shift",		.val = 0x02},
	{.opt = "right-shift",		.val = 0x20},
	{.opt = "left-alt",			.val = 0x04},
	{.opt = "right-alt",		.val = 0x40},
	{.opt = "left-meta",		.val = 0x08},
	{.opt = "right-meta",		.val = 0x80},
	{.opt = NULL}
};

static struct options kval[] = {
	{.opt = "a",			.val = 0x04},
	{.opt = "b",			.val = 0x05},
	{.opt = "c",			.val = 0x06},
	{.opt = "d",			.val = 0x07},
	{.opt = "e",			.val = 0x08},
	{.opt = "f",			.val = 0x09},
	{.opt = "g",			.val = 0x0a},
	{.opt = "h",			.val = 0x0b},
	{.opt = "i",			.val = 0x0c},
	{.opt = "j",			.val = 0x0d},
	{.opt = "k",			.val = 0x0e},
	{.opt = "l",			.val = 0x0f},
	{.opt = "m",			.val = 0x10},
	{.opt = "n",			.val = 0x11},
	{.opt = "o",			.val = 0x12},
	{.opt = "p",			.val = 0x13},
	{.opt = "q",			.val = 0x14},
	{.opt = "r",			.val = 0x15},
	{.opt = "s",			.val = 0x16},
	{.opt = "t",			.val = 0x17},
	{.opt = "u",			.val = 0x18},
	{.opt = "v",			.val = 0x19},
	{.opt = "w",			.val = 0x1a},
	{.opt = "x",			.val = 0x1b},
	{.opt = "y",			.val = 0x1c},
	{.opt = "z",			.val = 0x1d},
	{.opt = "1",			.val = 0x1e},
	{.opt = "2",			.val = 0x1f},
	{.opt = "3",			.val = 0x20},
	{.opt = "4",			.val = 0x21},
	{.opt = "5",			.val = 0x22},
	{.opt = "6",			.val = 0x23},
	{.opt = "7",			.val = 0x24},
	{.opt = "8",			.val = 0x25},
	{.opt = "9",			.val = 0x26},
	{.opt = "0",			.val = 0x27},
	{.opt = "return",		.val = 0x28},
	{.opt = "enter",		.val = 0x28},
	{.opt = "esc",			.val = 0x29},
	{.opt = "escape",		.val = 0x29},
	{.opt = "bckspc",		.val = 0x2a},
	{.opt = "backspace",	.val = 0x2a},

	{.opt = "tab",			.val = 0x2b},
	{.opt = "space",		.val = 0x2c},
	{.opt = "minus",		.val = 0x2d},
	{.opt = "dash",			.val = 0x2d},
	{.opt = "equals",		.val = 0x2e},
	{.opt = "equal",		.val = 0x2e},
	{.opt = "lbracket",		.val = 0x2f},
	{.opt = "rbracket",		.val = 0x30},
	{.opt = "backslash",	.val = 0x31},
	{.opt = "hash",			.val = 0x32},
	{.opt = "number",		.val = 0x32},
	{.opt = "semicolon",	.val = 0x33},
	{.opt = "quote",		.val = 0x34},
	{.opt = "backquote",	.val = 0x35},
	{.opt = "tilde",		.val = 0x35},
	{.opt = "comma",		.val = 0x36},
	{.opt = "period",		.val = 0x37},
	{.opt = "stop",			.val = 0x37},
	{.opt = "slash",		.val = 0x38},
	{.opt = "caps-lock",	.val = 0x39},
	{.opt = "capslock",		.val = 0x39},
	{.opt = "f1",			.val = 0x3a},
	{.opt = "f2",			.val = 0x3b},
	{.opt = "f3",			.val = 0x3c},
	{.opt = "f4",			.val = 0x3d},
	{.opt = "f5",			.val = 0x3e},
	{.opt = "f6",			.val = 0x3f},
	{.opt = "f7",			.val = 0x40},
	{.opt = "f8",			.val = 0x41},
	{.opt = "f9",			.val = 0x42},
	{.opt = "f10",			.val = 0x43},
	{.opt = "f11",			.val = 0x44},
	{.opt = "f12",			.val = 0x45},
	{.opt = "print",		.val = 0x46},
	{.opt = "scroll-lock",	.val = 0x47},
	{.opt = "scrolllock",	.val = 0x47},
	{.opt = "pause",		.val = 0x48},
	{.opt = "insert",		.val = 0x49},
	{.opt = "home",			.val = 0x4a},
	{.opt = "pageup",		.val = 0x4b},
	{.opt = "pgup",			.val = 0x4b},
	{.opt = "del",			.val = 0x4c},
	{.opt = "delete",		.val = 0x4c},
	{.opt = "end",			.val = 0x4d},
	{.opt = "pagedown",		.val = 0x4e},
	{.opt = "pgdown",		.val = 0x4e},
	{.opt = "right",		.val = 0x4f},
	{.opt = "left",			.val = 0x50},
	{.opt = "down",			.val = 0x51},
	{.opt = "up",			.val = 0x52},
	{.opt = "num-lock",		.val = 0x53},
	{.opt = "numlock",		.val = 0x53},
	{.opt = "kp-divide",	.val = 0x54},
	{.opt = "kp-multiply",	.val = 0x55},
	{.opt = "kp-minus",		.val = 0x56},
	{.opt = "kp-plus",		.val = 0x57},
	{.opt = "kp-enter",		.val = 0x58},
	{.opt = "kp-return",	.val = 0x58},
	{.opt = "kp-1",			.val = 0x59},
	{.opt = "kp-2",			.val = 0x5a},
	{.opt = "kp-3",			.val = 0x5b},
	{.opt = "kp-4",			.val = 0x5c},
	{.opt = "kp-5",			.val = 0x5d},
	{.opt = "kp-6",			.val = 0x5e},
	{.opt = "kp-7",			.val = 0x5f},
	{.opt = "kp-8",			.val = 0x60},
	{.opt = "kp-9",			.val = 0x61},
	{.opt = "kp-0",			.val = 0x62},
	{.opt = "kp-period",	.val = 0x63},
	{.opt = "kp-stop",		.val = 0x63},
	{.opt = "application",	.val = 0x65},
	{.opt = "power",		.val = 0x66},
	{.opt = "kp-equals",	.val = 0x67},
	{.opt = "kp-equal",		.val = 0x67},
	{.opt = "f13",			.val = 0x68},
	{.opt = "f14",			.val = 0x69},
	{.opt = "f15",			.val = 0x6a},
	{.opt = "f16",			.val = 0x6b},
	{.opt = "f17",			.val = 0x6c},
	{.opt = "f18",			.val = 0x6d},
	{.opt = "f19",			.val = 0x6e},
	{.opt = "f20",			.val = 0x6f},
	{.opt = "f21",			.val = 0x70},
	{.opt = "f22",			.val = 0x71},
	{.opt = "f23",			.val = 0x72},
	{.opt = "f24",			.val = 0x73},
	{.opt = "execute",		.val = 0x74},
	{.opt = "help",			.val = 0x75},
	{.opt = "menu",			.val = 0x76},
	{.opt = "select",		.val = 0x77},
	{.opt = "cancel",		.val = 0x78},
	{.opt = "redo",			.val = 0x79},
	{.opt = "undo",			.val = 0x7a},
	{.opt = "cut",			.val = 0x7b},
	{.opt = "copy",			.val = 0x7c},
	{.opt = "paste",		.val = 0x7d},
	{.opt = "find",			.val = 0x7e},
	{.opt = "mute",			.val = 0x7f},
	{.opt = "volume-up",	.val = 0x80}, // These are multimedia keys, they will not work on standard keyboard, they need a different USB descriptor
	{.opt = "volume-down",	.val = 0x81},
	{.opt = NULL}
};

struct telnet_keycode_translate {
	const char    *opt;
        const char    *seq;
};

struct telnet_keycode_translate _doto_keyboard[] = {
	{.opt = "~",	.seq = "left-shift backquote"},
	{.opt = "!",	.seq = "left-shift 1"},
	{.opt = "@",	.seq = "left-shift 2"},
	{.opt = "#",	.seq = "left-shift 3"},
	{.opt = "$",	.seq = "left-shift 4"},
	{.opt = "%",	.seq = "left-shift 5"},
	{.opt = "^",	.seq = "left-shift 6"},
	{.opt = "&",	.seq = "left-shift 7"},
	{.opt = "*",	.seq = "left-shift 8"},
	{.opt = "(",	.seq = "left-shift 9"},
	{.opt = ")",	.seq = "left-shift 0"},
	{.opt = "_",	.seq = "left-shift minus"},
	{.opt = "+",	.seq = "left-shift equal"},
	{.opt = "{",	.seq = "left-shift lbracket"},
	{.opt = "}",	.seq = "left-shift rbracket"},
	{.opt = "|",	.seq = "left-shift backslash"},
	{.opt = ":",	.seq = "left-shift semicolon"},
	{.opt = "\"",	.seq = "backslash"},
	{.opt = "<",	.seq = "left-shift comma"},
	{.opt = ">",	.seq = "left-shift stop"},
	{.opt = "?",	.seq = "left-shift slash"},
	{.opt = "A",	.seq = "left-shift a"},
	{.opt = "B",	.seq = "left-shift b"},
	{.opt = "C",	.seq = "left-shift c"},
	{.opt = "D",	.seq = "left-shift d"},
	{.opt = "E",	.seq = "left-shift e"},
	{.opt = "F",	.seq = "left-shift f"},
	{.opt = "G",	.seq = "left-shift g"},
	{.opt = "H",	.seq = "left-shift h"},
	{.opt = "I",	.seq = "left-shift i"},
	{.opt = "J",	.seq = "left-shift j"},
	{.opt = "K",	.seq = "left-shift k"},
	{.opt = "L",	.seq = "left-shift l"},
	{.opt = "M",	.seq = "left-shift m"},
	{.opt = "N",	.seq = "left-shift n"},
	{.opt = "O",	.seq = "left-shift o"},
	{.opt = "P",	.seq = "left-shift p"},
	{.opt = "Q",	.seq = "left-shift q"},
	{.opt = "R",	.seq = "left-shift r"},
	{.opt = "S",	.seq = "left-shift s"},
	{.opt = "T",	.seq = "left-shift t"},
	{.opt = "U",	.seq = "left-shift u"},
	{.opt = "V",	.seq = "left-shift w"},
	{.opt = "W",	.seq = "left-shift w"},
	{.opt = "X",	.seq = "left-shift x"},
	{.opt = "Y",	.seq = "left-shift y"},
	{.opt = "Z",	.seq = "left-shift z"},

	{.opt = "\x7f",	.seq = "backspace"},
	{.opt = "\xd",	.seq = "return"},
	{.opt = " ",	.seq = "space"},
	{.opt = "\t",	.seq = "tab"},
	{.opt = "-",	.seq = "minus"},
	{.opt = "=",	.seq = "equal"},
	{.opt = "/",	.seq = "backslash"},
	{.opt = "\\",	.seq = "slash"},
	{.opt = ",",	.seq = "comma"},
	{.opt = ";",	.seq = "semicolon"},
	{.opt = "[",	.seq = "lbracket"},
	{.opt = "]",	.seq = "rbracket"},
	{.opt = "'",	.seq = "quote"},
	{.opt = "`",	.seq = "backquote"},
	{.opt = ".",	.seq = "stop"},

	{.opt = "a",	.seq = "a"},
	{.opt = "b",	.seq = "b"},
	{.opt = "c",	.seq = "c"},
	{.opt = "d",	.seq = "d"},
	{.opt = "e",	.seq = "e"},
	{.opt = "f",	.seq = "f"},
	{.opt = "g",	.seq = "g"},
	{.opt = "h",	.seq = "h"},
	{.opt = "i",	.seq = "i"},
	{.opt = "j",	.seq = "j"},
	{.opt = "k",	.seq = "k"},
	{.opt = "l",	.seq = "l"},
	{.opt = "m",	.seq = "m"},
	{.opt = "n",	.seq = "n"},
	{.opt = "o",	.seq = "o"},
	{.opt = "p",	.seq = "p"},
	{.opt = "q",	.seq = "q"},
	{.opt = "r",	.seq = "r"},
	{.opt = "s",	.seq = "s"},
	{.opt = "t",	.seq = "t"},
	{.opt = "u",	.seq = "u"},
	{.opt = "v",	.seq = "v"},
	{.opt = "w",	.seq = "w"},
	{.opt = "x",	.seq = "x"},
	{.opt = "y",	.seq = "y"},
	{.opt = "z",	.seq = "z"},

	{.opt = "\x1b\x5b\x43",		.seq = "right"}, //right
	{.opt = "\x1b\x5b\x44",		.seq = "left"}, //left
	{.opt = "\x1b\x5b\x42",		.seq = "down"}, //down
	{.opt = "\x1b\x5b\x41",		.seq = "up"}, //up
	{.opt = "\x1b\x5b\x35\x7e",	.seq = "pgup"}, //pgup
	{.opt = "\x1b\x5b\x36\x7e",	.seq = "pgdown"}, //pgdown
	{.opt = "\x1b\x5f\x33\x7e",	.seq = "delete"},
	{.opt = "\x1b\x5b\x5a",		.seq = "tab"},

	{.opt = "\x1b\x4f\x50",		.seq = "f1"},
	{.opt = "\x1b\x4f\x51",		.seq = "f2"},
	{.opt = "\x1b\x4f\x52",		.seq = "f3"},
	{.opt = "\x1b\x4f\x53",		.seq = "f4"},
	{.opt = "\x1b\x4f\x54",		.seq = "f5"},
	{.opt = "\x1b\x4f\x55",		.seq = "f6"},
	{.opt = "\x1b\x4f\x56",		.seq = "f7"},
	{.opt = "\x1b\x4f\x57",		.seq = "f8"},
	{.opt = "\x1b\x4f\x58",		.seq = "f9"},
	{.opt = "\x1b\x4f\x59",		.seq = "f10"},
	{.opt = "\x1b\x4f\x60",		.seq = "f11"},
	{.opt = "\x1b\x4f\x61",		.seq = "f12"},
	{.opt = "\x1b",			.seq = "escape"},
};

int read_doto_code(int peerfd, char buf[], size_t len)
{
    int i;
    char keybuf[6];
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
    
    int keylen = read(peerfd, keybuf, sizeof(keybuf) -1);
    if (keylen <= 0) return keylen;

    keybuf[keylen] = 0;

    char *optout = buf;
    const char *optkey = keybuf;

    while (*optkey) {
	for (i = 0; i < ARRAY_SIZE(_doto_keyboard); i++) {
	    const char *key = _doto_keyboard[i].opt;
	    size_t klen = strlen(key);

	    if (strncmp(key, optkey, klen) == 0 && buf + len > optout) {
		int size = buf + len - optout;
		optout += snprintf(optout, size, "%s ", _doto_keyboard[i].seq);
		optkey += (klen -1);
		break;
	    }
	}

	optkey++;
    }

    for (i = 0; i < keylen; i++)fprintf(stderr, "%02x ", keybuf[i]);
    fprintf(stderr, "LINE: %s\n", buf);
    return optout - buf;
}

int keyboard_fill_report(char report[8], char buf[BUF_LEN], int *hold)
{
	char *tok = strtok(buf, " ");
	int key = 0;
	int i = 0;

	for (; tok != NULL; tok = strtok(NULL, " ")) {

		if (strncmp(tok, "--", 2) == 0)
			tok += 2;

		if (strcmp(tok, "quit") == 0)
			return -1;

		if (strcmp(tok, "hold") == 0) {
			*hold = 1;
			continue;
		}

		if (key < 6) {
			for (i = 0; kval[i].opt != NULL; i++)
				if (strcmp(tok, kval[i].opt) == 0) {
					report[2 + key++] = kval[i].val;
					break;
				}
			if (kval[i].opt != NULL)
				continue;
		}

		for (i = 0; kmod[i].opt != NULL; i++)
			if (strcmp(tok, kmod[i].opt) == 0) {
				report[0] = report[0] | kmod[i].val;
				break;
			}
		if (kmod[i].opt != NULL)
			continue;

		if (key < 6)
			fprintf(stderr, "unknown option: %s\n", tok);
	}

	return 8;
}

static struct options mmod[] = {
	{.opt = "--b1", .val = 0x01},
	{.opt = "--b2", .val = 0x02},
	{.opt = "--b3", .val = 0x04},
	{.opt = NULL}
};

int mouse_fill_report(char report[8], char buf[BUF_LEN], int *hold)
{
	char *tok = strtok(buf, " ");
	int mvt = 0;
	int i = 0;
	for (; tok != NULL; tok = strtok(NULL, " ")) {

		if (strcmp(tok, "--quit") == 0)
			return -1;

		if (strcmp(tok, "--hold") == 0) {
			*hold = 1;
			continue;
		}

		for (i = 0; mmod[i].opt != NULL; i++)
			if (strcmp(tok, mmod[i].opt) == 0) {
				report[0] = report[0] | mmod[i].val;
				break;
			}
		if (mmod[i].opt != NULL)
			continue;

		if (!(tok[0] == '-' && tok[1] == '-') && mvt < 2) {
			errno = 0;
			report[1 + mvt++] = (char)strtol(tok, NULL, 0);
			if (errno != 0) {
				fprintf(stderr, "Bad value:'%s'\n", tok);
				report[1 + mvt--] = 0;
			}
			continue;
		}

		fprintf(stderr, "unknown option: %s\n", tok);
	}
	return 3;
}

static struct options jmod[] = {
	{.opt = "--b1",		.val = 0x10},
	{.opt = "--b2",		.val = 0x20},
	{.opt = "--b3",		.val = 0x40},
	{.opt = "--b4",		.val = 0x80},
	{.opt = "--hat1",	.val = 0x00},
	{.opt = "--hat2",	.val = 0x01},
	{.opt = "--hat3",	.val = 0x02},
	{.opt = "--hat4",	.val = 0x03},
	{.opt = "--hatneutral",	.val = 0x04},
	{.opt = NULL}
};

int joystick_fill_report(char report[8], char buf[BUF_LEN], int *hold)
{
	char *tok = strtok(buf, " ");
	int mvt = 0;
	int i = 0;

	*hold = 1;

	/* set default hat position: neutral */
	report[3] = 0x04;

	for (; tok != NULL; tok = strtok(NULL, " ")) {

		if (strcmp(tok, "--quit") == 0)
			return -1;

		for (i = 0; jmod[i].opt != NULL; i++)
			if (strcmp(tok, jmod[i].opt) == 0) {
				report[3] = (report[3] & 0xF0) | jmod[i].val;
				break;
			}
		if (jmod[i].opt != NULL)
			continue;

		if (!(tok[0] == '-' && tok[1] == '-') && mvt < 3) {
			errno = 0;
			report[mvt++] = (char)strtol(tok, NULL, 0);
			if (errno != 0) {
				fprintf(stderr, "Bad value:'%s'\n", tok);
				report[mvt--] = 0;
			}
			continue;
		}

		fprintf(stderr, "unknown option: %s\n", tok);
	}
	return 4;
}

void print_options(char c)
{
	int i = 0;

	if (c == 'k') {
		printf("	keyboard options:\n"
		       "		hold\n");
		for (i = 0; kmod[i].opt != NULL; i++)
			printf("\t\t%s\n", kmod[i].opt);
		printf("\n	keyboard values:\n"
		       "		[a-z] or [0-9] or\n");
		for (i = 0; kval[i].opt != NULL; i++)
			printf("\t\t%-8s%s", kval[i].opt, i % 2 ? "\n" : "");
		printf("\n");
	} else if (c == 'm') {
		printf("	mouse options:\n"
		       "		--hold\n");
		for (i = 0; mmod[i].opt != NULL; i++)
			printf("\t\t%s\n", mmod[i].opt);
		printf("\n	mouse values:\n"
		       "		Two signed numbers\n\n");
	} else {
		printf("	joystick options:\n");
		for (i = 0; jmod[i].opt != NULL; i++)
			printf("\t\t%s\n", jmod[i].opt);
		printf("\n	joystick values:\n"
		       "		three signed numbers\n"
		       "--quit to close\n");
	}
}

#define PORT 3333

int main(int argc, const char *argv[])
{
	const char *filename = NULL;
	int fd = 0;
	char buf[BUF_LEN];
	int cmd_len;
	char report[8];
	int to_send = 8;
	int hold = 0;
	fd_set rfds;
	int retval, i;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s devname mouse|keyboard|joystick\n",
			argv[0]);

		print_options('k');
		print_options('m');
		print_options('j');

		return 1;
	}

	if (argv[2][0] != 'k' && argv[2][0] != 'm' && argv[2][0] != 'j')
	  return 2;

	filename = argv[1];

	if ((fd = open(filename, O_RDWR, 0666)) == -1) {
		perror(filename);
		return 3;
	}

	int enable = 1;
	struct sockaddr_in6 servaddr;
	int peerfd = -1;
	int sockfd = socket(AF_INET6, SOCK_STREAM, 0);

	servaddr.sin6_family = AF_INET6;
	servaddr.sin6_port = htons(*argv[3]? atoi(argv[3]): PORT);
	servaddr.sin6_addr = in6addr_any;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

	// Binding newly created socket to given IP and verification
	if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
		printf("socket bind failed...\n");
		exit(0);
	}

	if (listen(sockfd, 1) != 0) {
		printf("socket listen failed...\n");
		exit(0);
	}

	while (42) {

		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(fd, &rfds);
		FD_SET(sockfd, &rfds);
		if (peerfd != -1) 
			FD_SET(peerfd, &rfds);

		retval = select(peerfd != -1? peerfd + 1: sockfd + 1, &rfds, NULL, NULL, NULL);
		if (retval == -1 && errno == EINTR)
			continue;
		if (retval < 0) {
			perror("select()");
			return 4;
		}

		if (FD_ISSET(fd, &rfds)) {
			cmd_len = read(fd, buf, BUF_LEN - 1);
			printf("recv report:");
			for (i = 0; i < cmd_len; i++)
				printf(" %02x", buf[i]);
			printf("\n");
		}

		if (FD_ISSET(sockfd, &rfds)) {
			close(peerfd);
			peerfd = accept(sockfd, NULL, NULL);
			if (peerfd != -1) write(peerfd,"\377\375\042\377\373\001",6);
			printf("accept: %d\n", peerfd);
		}

		if (peerfd != -1 && FD_ISSET(peerfd, &rfds)) {
			memset(report, 0x0, sizeof(report));
			cmd_len = read_doto_code(peerfd, buf, BUF_LEN - 1);
			if (cmd_len > 0) goto doto_code;
		}

		if (FD_ISSET(STDIN_FILENO, &rfds)) {
			memset(report, 0x0, sizeof(report));
			cmd_len = read(STDIN_FILENO, buf, BUF_LEN - 1);

doto_code:
			if (cmd_len == 0)
				break;

			buf[cmd_len - 1] = '\0';
			hold = 0;

			memset(report, 0x0, sizeof(report));
			if (argv[2][0] == 'k')
				to_send = keyboard_fill_report(report, buf, &hold);
			else if (argv[2][0] == 'm')
				to_send = mouse_fill_report(report, buf, &hold);
			else
				to_send = joystick_fill_report(report, buf, &hold);

			if (to_send == -1)
				break;

			if (write(fd, report, to_send) != to_send) {
				perror(filename);
				return 5;
			}

			if (report[0] && argv[2][0] == 'k') usleep(10000);

			if (!hold) {
				memset(report, 0x0, sizeof(report));
				if (write(fd, report, to_send) != to_send) {
					perror(filename);
					return 6;
				}
			}
		}
	}

	close(sockfd);
	close(fd);
	return 0;
}

