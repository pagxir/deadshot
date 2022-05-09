#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#define PORT 3535
#define SEQ_LT(a, b) ((int)((a) - (b)) < 0)
#define SEQ_LEQ(a, b) ((int)((a) - (b)) <= 0)
#define SEQ_GEQ(a, b) ((int)((a) - (b)) >= 0)

typedef unsigned int tcp_seq;

static tcp_seq _ts_recent = 0;
static tcp_seq _seq_rcv_nxt = 0;

static tcp_seq _track_id = 0;
static tcp_seq _stat_pktval = 0;
static tcp_seq _stat_receive = 0;

struct sack_score {
  tcp_seq start;
  tcp_seq end;
};

struct bbr_info {
  tcp_seq trackid;
  tcp_seq seq_pkt;
  tcp_seq seq_ack;
  tcp_seq ts_val;
  tcp_seq ts_ecr;
  tcp_seq pkt_val;

  int nsack;
  struct sack_score sacks[5]; 
};

#define MAX_SACK 64000
static int _score_count = 0;
static struct sack_score _score_board[MAX_SACK];

static unsigned char TUNNEL_PADDIND_DNS[] = {
  0x20, 0x88, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x04, 0x77, 0x77, 0x77,
  0x77, 0x00, 0x00, 0x01, 0x00, 0x01
};

#define LEN_PADDING_DNS sizeof(TUNNEL_PADDIND_DNS)

#define SND_MAX_RCV_WND 819200
// static unsigned char rx_bitmap[8192] = {};

static int dump()
{
  int i;
  printf("count %d\n", _score_count);
  for (i = 0; i < _score_count; i++)
  {
    printf("%d: %x %x\n", i, _score_board[i].start, _score_board[i].end);
  }
}

static int update_score_board(tcp_seq seq)
{
  int i, old = 0;
  int num_sack = 1;
  struct sack_score ss1 = {};
  struct sack_score *item = NULL;
  struct sack_score newscore[MAX_SACK];

  ss1.start = seq;
  ss1.end = seq + 1;

  for (i = 0; i < _score_count; i++) {
    item = &_score_board[i];

    if (SEQ_LT(ss1.end, item->start)
	|| SEQ_LT(item->end, ss1.start)) {
      if (num_sack >= MAX_SACK) dump();
      assert(num_sack < MAX_SACK);
      newscore[num_sack++] = *item;
    } else {

      if (SEQ_LT(seq, item->end) &&
	  SEQ_GEQ(seq, item->start)) {
	// printf("seq %x start %x end %x\n", seq, item->start, item->end);
	old = 1;
      }

      if (SEQ_LT(item->start, ss1.start))
	ss1.start = item->start;

      if (SEQ_LT(ss1.end, item->end))
	ss1.end = item->end;
    }
  }

next:
  newscore[0] = ss1;
  memcpy(_score_board, newscore, num_sack * sizeof(ss1));
  _score_count = num_sack;
  return old;
}

int main(int argc, char *argv[])
{ 
  int i;
  int error;
  int nbytes;
  char buff[1500];
  struct bbr_info bbrinfo, *pbbr;
  struct sockaddr_in serv, client;
  socklen_t addr_len = sizeof(client);

  int s = socket(AF_INET, SOCK_DGRAM, 0);
  assert (s != -1);

  int rcvBufferSize;
  int sockOptSize = sizeof(rcvBufferSize);
  getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvBufferSize, &sockOptSize);
  printf("rcvbufsize: %d\n", rcvBufferSize);

  bzero(&serv, sizeof(serv));
  if (strcmp(argv[1], "-l") == 0) {
    serv.sin_family = AF_INET;
    serv.sin_port = htons(atoi(argv[3]));
    serv.sin_addr.s_addr = inet_addr(argv[2]);
    error = bind(s, (struct sockaddr *)&serv, sizeof(serv));
    assert (error == 0);
  } else if (strcmp(argv[1], "-c") == 0) {
    client.sin_family = AF_INET;
    client.sin_port = htons(atoi(argv[3]));
    client.sin_addr.s_addr = inet_addr(argv[2]);
    memcpy(buff, TUNNEL_PADDIND_DNS, LEN_PADDING_DNS);
    sendto(s, buff, LEN_PADDING_DNS + 1, 0, (struct sockaddr *)&client, addr_len);
  } else if (strcmp(argv[1], "-h") == 0) {
    fprintf(stderr, "-h\n");
    fprintf(stderr, "-l <address> <port> \n");
    fprintf(stderr, "-c <address> <port> \n");
  } else {
    exit(-1);
  }

  tcp_seq _new_tsval = 0;
  tcp_seq _new_pkg_seq = 0;

  time_t last_display = time(NULL);
  int flags = 0, first = 1, _stat_dupdat = 0;

  for ( ; ; ) {
    if (last_display != time(NULL)) {
      printf("receive: %d, dupdata %d\n", _stat_receive, _stat_dupdat);
      last_display = time(NULL);
    }

    nbytes = recvfrom(s, buff, sizeof(buff), 0, (struct sockaddr *)&client, &addr_len); // once success, we get client.
    if (nbytes < sizeof(bbrinfo) + LEN_PADDING_DNS || nbytes == -1) {
      continue;
    }

    pbbr = (struct bbr_info *)(buff + LEN_PADDING_DNS);
    bbrinfo.seq_pkt = ntohl(pbbr->seq_pkt);
    bbrinfo.seq_ack = ntohl(pbbr->seq_ack);
    bbrinfo.ts_val = ntohl(pbbr->ts_val);
    bbrinfo.ts_ecr = ntohl(pbbr->ts_ecr);
    bbrinfo.pkt_val = ntohl(pbbr->pkt_val);

    if (_track_id != pbbr->trackid || first == 1) {
      // memset(rx_bitmap, 0, sizeof(rx_bitmap));
      _track_id = pbbr->trackid;
      _score_count = 0;
      _seq_rcv_nxt = bbrinfo.seq_pkt + 1;
      _ts_recent   = bbrinfo.ts_val;
      _stat_pktval = bbrinfo.pkt_val;
      _stat_receive = 1;
      _stat_dupdat = 0;
      first = 0;
      goto ack_then_drop;
    }

    if (SEQ_LT(_seq_rcv_nxt + SND_MAX_RCV_WND, bbrinfo.seq_pkt)) {
      printf("out of range\n");
      goto ack_then_drop;
    }

    _stat_receive++;
    if (SEQ_LT(_ts_recent, bbrinfo.ts_val)) {
      _stat_pktval = bbrinfo.pkt_val;
      _ts_recent = bbrinfo.ts_val;
    }

    if (SEQ_LT(bbrinfo.seq_pkt, _seq_rcv_nxt)) {
      // printf("out of date\n");
      _stat_dupdat ++;
      goto ack_then_drop;
    }

    if (bbrinfo.seq_pkt != _seq_rcv_nxt) {
      _stat_dupdat += update_score_board(bbrinfo.seq_pkt);
      goto ack_then_drop;
    }

    update_score_board(bbrinfo.seq_pkt);
    assert (_score_count > 0);
    _seq_rcv_nxt = _score_board[0].end;
    _score_count--;
    memmove(_score_board, _score_board + 1, _score_count * sizeof(_score_board[0]));

    if (flags == 0) {
      flags = 1;
      continue;
    }

ack_then_drop:
    pbbr->seq_pkt = ntohl(_new_pkg_seq++);
    pbbr->seq_ack = ntohl(_seq_rcv_nxt);
    pbbr->ts_val = ntohl(_new_tsval++);
    pbbr->ts_ecr = ntohl(_ts_recent);
    pbbr->pkt_val = ntohl(_stat_receive);

    int nsack = _score_count < 5? _score_count: 5;
    pbbr->nsack   = htonl(nsack);
    for (i = 0; i < nsack; i++) {
      pbbr->sacks[i].start = htonl(_score_board[i].start);
      pbbr->sacks[i].end = htonl(_score_board[i].end);
    }

    sendto(s, buff, LEN_PADDING_DNS + sizeof(bbrinfo), 0, (struct sockaddr *)&client, sizeof(client));
    flags = 0;
  }

  close(s);
  return 0;
}

