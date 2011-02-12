#include "stdafx.h"
#include <winsock.h>
#include <signal.h>
#include <assert.h>

#define  close closesocket

typedef int socklen_t;

int wait_ack(int fudp, u_short ackno, int *pcancel)
{
    int result;
    char buffer[1024];
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fudp, &readfds);
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    if (select(fudp + 1, &readfds, 0, 0, &timeout)) {
        u_short  *ackhdr = (u_short *)buffer;
        result = recv(fudp, buffer, sizeof(buffer), 0);
        if (result < 4)
            return 0;
        if (ackhdr[0] == htons(4)
            && ackhdr[1] == htons(ackno))
            return 1;
        if (ackhdr[0] == htons(5))
            pcancel[0] = 1;
    }

    return 0;
}

int stable_send(int fudp, const void *sndbuf, socklen_t len,  u_short ackno, int *pcancel)
{
    const char *psndbuf = (const char *)sndbuf;
    int result = send(fudp, psndbuf, len, 0);

    for (int i = 0; i < 5 && result == len && *pcancel == 0; i++) {
        if (wait_ack(fudp, ackno, pcancel))
            return 1;
        result = send(fudp, psndbuf, len, 0);
    }

    if (result != len)
        pcancel[0] = 1;
    return 0;
}

int tftp_exec(const char *buffer, socklen_t len,
              const struct sockaddr *paddr, socklen_t sinlen)
{
    int result;
    int count = 0;
    u_short  tftpidx, *tftphdr, *reqhdr;
    
    char sndbuf[1024];
    int fudp = socket(AF_INET, SOCK_DGRAM, 0);
    assert (fudp != -1);
    result = connect(fudp, paddr, sinlen);
    if (result == -1)
        return result;
    
    char msg_deny[]="Access Deny";
    char msg_badop[]="Invaliadate Operation";
    char msg_notfound[]="TFTP File Not Found";

    do {
        reqhdr = (u_short *)buffer;
        tftphdr = (u_short *)sndbuf;
        if (len < 9 || reqhdr[0] != htons(1)) {     
            tftphdr[0] = htons(5);
            if (len < 9)
                break;
            count = 4;
            if (reqhdr[1] == htons(2)) {
                tftphdr[1] = htons(2); count += sizeof(msg_deny);
                memcpy(tftphdr+2, msg_deny, sizeof(msg_deny));
            } else {
                tftphdr[1] = htons(4); count += sizeof(msg_badop);
                memcpy(tftphdr+2, msg_badop, sizeof(msg_badop));
            }
            send(fudp, sndbuf, count, 0);
        } else {
            FILE *fbin = fopen(buffer+2, "rb");
            if (fbin == NULL) {
                tftphdr[0] = htons(5);
                tftphdr[1] = htons(2); count = sizeof(msg_notfound) + 4;
                memcpy(tftphdr + 2, msg_notfound, sizeof(msg_notfound));
                send(fudp, sndbuf, count, 0);
                break;
            }
            printf("get file: %s\n", buffer + 2);
            tftpidx = 1;
            tftphdr = (u_short *)sndbuf;
            int cancel = 0;
            do {
                tftphdr[0] = htons(3);
                tftphdr[1] = htons(tftpidx);
                count = fread(sndbuf + 4, 1, 512, fbin);
                if (!stable_send(fudp, sndbuf, count+4, tftpidx, &cancel)) {
                    printf("error ocurr!\n");
                    break;
                }
                tftpidx++;
            }while(count > 0 && cancel == 0);
            fclose(fbin);
        }
    } while (FALSE);
    close(fudp);
    return 0;
}

int tftpd_run(int argc, char *argv[])
{
    int result;
    struct sockaddr_in sinaddr;
    struct sockaddr *paddr = NULL;
    int fudp = socket(AF_INET, SOCK_DGRAM, 0);
    paddr = (struct sockaddr *)&sinaddr;
    sinaddr.sin_family = AF_INET;
    sinaddr.sin_port  = htons(69);
    sinaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    result = bind(fudp, paddr, sizeof(sinaddr));

    for (;;) {
        int len, sinlen;
        char buffer[1024];
        sinlen = sizeof(sinaddr);
        len = recvfrom(fudp, buffer, sizeof(buffer),
            0,  paddr, &sinlen);
        if (len > 0)
            tftp_exec(buffer, len, paddr, sinlen);
    }

    close(fudp);
    return 0;
}

