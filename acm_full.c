#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

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

#define M(x) ((x) - 'a')

static char _output[10001] = {};

int get_result(const char *buf) {
  int i;
  int ch;
  int j, k;
  int len = strlen(buf);

  int stat[26] = {};
  int infly[26] = {};
  int outfly[26] = {};
  char *left = _output, *right = _output;

  for (len = 0; buf[len]; len++) {
    ch = M(buf[len]);
    outfly[ch]++;
  }

  for (i = 0; i < 26; i++) {
    stat[i] = (outfly[i] >> 1);
  }

  for (i = 0; i < len; i++) {
    ch = M(buf[i]);

    outfly[ch]--;
    if (stat[ch] <= infly[ch]) {
      continue;
    }

    while (right > left && buf[i] < *(right - 1)) {
      int cwh = M(*(right - 1));

      if (outfly[cwh] + infly[cwh] <= stat[cwh]) {
        while (left < right) {
          infly[M(*left)]--;
          stat[M(*left)]--;
          left++;
        }
        break;
      }

      infly[cwh]--;
      *right = 0;
      right--;
    }

    // if (infly[ch] < stat[ch]) {
    *right++ = buf[i];
    *right = 0;
    infly[ch]++;
    // }
  }

  *right = 0;
  printf("%s\n", _output);
  return 0;
}

int main(int argc, char *argv[]) {
  int i;
  int len;

  char *c;
  char buf[10001];

  c = fgets(buf, sizeof(buf), stdin);
  if (c == NULL) {
    return 0;
  }

  len = strlen(buf);
  if (!isalpha(buf[len - 1]))
    buf[--len] = 0;

  for (i = 0; i < len / 2; i++) {
    char tmp = buf[i];
    buf[i] = buf[len - i - 1];
    buf[len - i - 1] = tmp;
  }

  // fprintf(stderr, "%s\n", buf);
  get_result(buf);

  return 0;
}

