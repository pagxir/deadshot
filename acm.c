#include <stdio.h>
#include <string.h>

#if 0
字符串处理
描述

定义字符串的以下几种操作：

reverse(A)获得A字符串的逆序字符串，例如reverse("abc") = "cba"
shuffle(A)获得A随机重排的字符串，例如shuffle("dog") ∈ {"dog", "dgo", "odg", "ogd", "gdo", "god"}
merge(A1, A2)，合并A1和A2两个字符串，合并过程中只保证A1和A2本身字母的顺序，例如merge("qwe", "asd")的可能结果有很多， “qweasd”和“qwased”都是可能的取值。现在给定一个字符串S，S ∈merge(reverse(A), shuffle(A))。求以字母表顺序排序的A的最小值。

输入描述

输入一个字符串S。


输出描述

输出一个字符串，为A的最小取值。
#endif

static int stat[256] = {};
static int strbuf[256][256] = {};

int get_result(const char *buf)
{
  int i, j, p;
  int ch, cnt;
  int len = strlen(buf);

  for (i = 0; i < len; i++) {
	ch = buf[i];
    cnt = stat[ch]++;
	strbuf[cnt][ch] = i;
  }

  char chmask[256] = {};
  char restore[256] = {};
  memset(chmask, '@', len);

  int low = 'a';
  int high = 'z';
  int set_high = 0;
  int low_limit = -1;
  int high_limit = 256;

  while (low <= high) {
	  int total = 0;
	  memcpy(restore, chmask, len);
	  if (set_high) {
		  while (stat[high] == 0 && low <= high) high --;
		  if (low > high) break;

		  int limit = 0;
		  for (j = stat[high] - 1; j >= 0; j--) {
			  p = strbuf[j][high];
			  if (p < high_limit && total * 2 < stat[high]) {
				  limit = p;
				  chmask[p] = high;
				  total++;
			  }
		  }

		  if (total * 2 >= stat[high]) {
			  low_limit = limit;
			  high--;
		  } else {
			  set_high = 0;
			  memcpy(chmask, restore, len);
		  }
	  } else {
		  while (stat[low] == 0 && low <= high) low ++;
		  if (low > high) break;

		  int limit = 0;
		  for (j = 0; j < stat[low]; j++) {
			  p = strbuf[j][low];
			  if (p > low_limit && total * 2 < stat[low]) {
				  chmask[p] = low;
				  limit = p;
				  total++;
			  }
		  }

		  if (total * 2 >= stat[low]) {
			  low_limit = limit;
			  low++; 
		  } else {
			  set_high = 1;
			  memcpy(chmask, restore, len);
		  }
	  }
  }

  char *src, *dst = chmask;
  for (src = chmask; *src; src++) {
	  if (src[0] != '@') *dst++ = *src;
  }

  *dst = 0;
  printf("%s", chmask);
  return 0;
}

int main(int argc, char *argv[])
{
	int i;
	int len;

	char * c;
	char buf[256];
	char out[256];

	c = fgets(buf, sizeof(buf), stdin);
	if (c == NULL) {
		return 0;
	}

	len = strlen(buf) - 1;
	buf[len] = 0;

	for (i = 0; i < len/2; i++) {
		char tmp = buf[i];
		buf[i] = buf[len - i - 1];
		buf[len - i - 1] = tmp;
	}

	get_result(buf);

	return 0;
}
