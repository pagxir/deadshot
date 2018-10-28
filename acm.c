
#include <stdio.h>
#include <string.h>
#include <assert.h>

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

// echo igighhbbdacdac|./a.out
static int stat[26] = {};
static int stat1[26] = {};

int get_result(const char *buf)
{
	int i, j, p;
	int ch, progress = 0;
	int len = strlen(buf);

	for (i = 0; i < len; i++) {
		ch = buf[i];
		stat[M(ch)]++;
	}

	int left = -1, right = 25;
	for (i = 0; i < 26; i++) {
		if (stat[i] == 0) continue;

		stat[i] /= 2;

		if (left == -1) left = i;

		right = i;
	}

	progress = len/2;
	while (progress > 0) {

		for (i = left; i <= right; i++) {
			int pos = -1;
			if (stat[i] == 0) continue;

			memcpy(stat1, stat, sizeof(stat));
			for (j = 0; buf[j]; j++) {
				if (M(buf[j]) == i) {
					pos = j;
					break;
				}
			}

			assert(pos != -1);
			for (j = pos; buf[j]; j++) {
				if (stat1[M(buf[j])])
					stat1[M(buf[j])]--;
			}

			int again = 0;
			for (j = left; j <= right; j++) {
				if (stat1[j] != 0) {
					again = 1;
			// printf("%s break %c; sel %c, %d\n", buf, j + 'a', i + 'a', stat1[j]);
					break;
				}
			}

			if (again == 0) {
				// printf("|%c\n", 'a' + i);
				printf("%c", 'a' + i);
				buf = buf + pos + 1;
				progress--;
				stat[i]--;
				break;
			}

			// printf("tontinue;\n");
		}
	}

    printf("\n");
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
