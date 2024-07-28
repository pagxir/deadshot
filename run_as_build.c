// filename: uid.c 
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#if 0
int main() {

    uid_t ruid, euid, suid;

    // Get the real, effective, and saved user IDs
    if (getresuid(&ruid, &euid, &suid) == -1) {
        perror("getresuid");
        return 1;
    }

    // Display the user IDs
    printf("Real      UID: %d\n", ruid);
    printf("Effective UID: %d\n", euid);
    printf("Saved     UID: %d\n", suid);

    // file /etc/hosts is owned by root, and only root can open it
    // in write mode. Normal/unprovileged users can only open it in read mode.

    /*See if we can open the /etc/hosts file for reading and writing, as the EUID*/
    printf("open: %d\n", open("/etc/hosts", O_RDWR));
    /* access() tests what the RUID can do. We check 'writing' in this case */
    printf("access: %d\n", access("/etc/hosts", W_OK));

    printf("--\n");
    // drop the privileges in the EUID by setting it with the RUID, and re-try
    seteuid(ruid);

    if (getresuid(&ruid, &euid, &suid) == -1) {
        perror("getresuid");
        return 1;
    }

    printf("Real      UID: %d\n", ruid);
    printf("Effective UID: %d\n", euid);
    printf("Saved     UID: %d\n", suid);

    /*See if we can open the /etc/hosts file for reading and writing, as the EUID*/
    printf("open: %d\n", open("/etc/hosts", O_RDWR));
    /* access() tests what the RUID can do. We check 'writing' in this case */
    printf("access: %d\n", access("/etc/hosts", W_OK));

    return 0;
}
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/fsuid.h>

int main(int argc, char *argv[])
{
    uid_t ruid, euid, suid;

    if (getresuid(&ruid, &euid, &suid)) exit(-1);

    if (argc == 1) {
	    printf("Real      UID: %d\n", ruid);
	    printf("Effective UID: %d\n", euid);
	    printf("Saved     UID: %d\n", suid);
	    printf("Saved     pid: %d pgid %d\n", getpid(), getpgid(0));
	    exit(0);
    }

    if (argc > 1) {
	    const char * cmd = argv[0];
	    const char * last = argv[0];

	    while (*cmd) {
		    if (*cmd == '_') last = cmd;
		    cmd++;
	    }

	    if (!strcmp(last, "_euid")) setresuid(euid, euid, euid);
	    else if (!strcmp(last, "_suid")) setresuid(euid, ruid, suid);
	    else if (!strcmp(last, "_ruid")) setresuid(euid, ruid, ruid);
	    else if (!strcmp(last, "_fseuid")) {
		    setfsuid(euid);
		    setresuid(ruid, ruid, ruid);
	    } else if (!strcmp(last, "_fsruid")) {
		    setfsuid(ruid);
		    setresuid(euid, euid, euid);
	    } else {
		    printf("CMD: %s\n", last);
	    }

		if (!strcmp(argv[1], "--dump")) {
			printf("Real      UID: %d\n", ruid);
			printf("Effective UID: %d\n", euid);
			printf("Saved     UID: %d\n", suid);
			exit(0);
		}

		int status;
		time_t now = 0, end = 0;
		struct tm first, finish;
		int pipefds[2];
		int rc = pipe(pipefds);

		pid_t pid = fork();
#if 0
		if (pid == 0) {
			execvp(argv[1], argv + 1);
			exit(-1);
		} else if (pid > 0) {
			time(&now);
			waitpid(pid, &status, 0);
			time(&end);
		}
#endif
		if (pid == 0) {
			close(pipefds[1]);
			time(&now);
			read(pipefds[0], &status, sizeof(status));
			time(&end);
		} else if (pid > 0) {
			close(pipefds[0]);
			execvp(argv[1], argv + 1);
			exit(-1);
		}

		if (now + 7 < end) {
			localtime_r(&now, &first);
			localtime_r(&end, &finish);
			fprintf(stderr, "\n");
			fprintf(stderr, "start  %d %02d:%02d:%02d\n", first.tm_mday, first.tm_hour, first.tm_min, first.tm_sec);
			fprintf(stderr, "finish %d %02d:%02d:%02d\n", finish.tm_mday, finish.tm_hour, finish.tm_min, finish.tm_sec);
			fprintf(stderr, "use %d seconds \n", end - now);
		}
    }

    return 0;
}

