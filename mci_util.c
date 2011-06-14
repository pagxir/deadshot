#include <stdio.h>
#include <windows.h>
#include <mmsystem.h>

#if 0
open new type WAVEAudio alias ll
record ll
stop ll
save ll 3.wav
close ll
#endif

static char *crlf_strip(char *line)
{
	char *carp;
	char *startp;

   	startp = carp = line;
	while (*startp == ' ')startp++;

   	while (*carp) {
	   	if (*carp == '\r') {
		   	*carp = 0;
		   	break;
	   	}

		if (*carp == '\n') {
		   	*carp = 0;
		   	break;
	   	}
	   
		carp++;
   	}

	return startp;
}

int main(int argc, char *argv[])
{
	int quited = 0;
	char *mci_cmd;
	char mci_text[2048];

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "quit") == 0) {
			quited = 1;
			break;
		}

	   	mciSendString(argv[i], NULL, 0, NULL);
		fprintf(stderr, "%s\n", argv[i]);
	}

	Sleep(10000);

	while (quited == 0) {
		if (!fgets(mci_text, sizeof(mci_text), stdin)) {
			fprintf(stderr, "end of user input");
			break;
		}

		mci_cmd = crlf_strip(mci_text);
		if (strcmp(mci_cmd, "quit") == 0) {
			quited = 1;
			break;
		}

		if (*mci_cmd != 0) {
		   	mciSendString(mci_cmd, NULL, 0, NULL);
		   	fprintf(stderr, "%s\n", mci_cmd);
		}
	}

	return 0;
}

