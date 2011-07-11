#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* this is an small tool to update 15 person identity card number
 * to new 18 person identity card number.
 */

static char *getpid18(const char *pid)
{
    int i;
    int cond = 0;
    uint8_t icode = 0;
    uint32_t sumcode = 0;
    static char __pidbuf[20];

    if (pid != NULL)
        cond = strlen(pid);

    switch(cond)
    {
        case 15:
            __pidbuf[6] = '1';
            __pidbuf[7] = '9';
            memcpy(__pidbuf, pid, 6);
            memcpy(__pidbuf + 8, pid + 6, 9);
            break;

        case 17:
            memcpy(__pidbuf, pid, 17);
            break;

        default:
            return (char*)pid;
    }

    static const uint8_t weight[] = {
        7, 9, 10, 5, 8, 4, 2, 1, 6,
        3, 7, 9, 10, 5, 8, 4, 2
    };

    for (i = 0; i < 17; i++) {
        icode = (uint8_t)__pidbuf[i] - '0';
        sumcode += icode * weight[i];
    }

    uint8_t imode = sumcode % 11;

    static const char lastcode[] = {
        "10X98765432"
    };

    __pidbuf[17] = lastcode[imode];
    __pidbuf[18] = 0;

    return __pidbuf;
}

int main(int argc, char *argv[])
{
    int i;
    for (i = 1; i < argc; i++)
        printf("%s\n", getpid18(argv[i]));
    return 0;
}

