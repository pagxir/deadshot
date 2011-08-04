#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <stdint.h>
#include "large_digit.h"

#define RSA_NBIT  768


#define DWORD uint32_t
DWORD GetTickCount(void)
{ 
	struct timespec ts1;
	clock_gettime(CLOCK_MONOTONIC, &ts1);
	return ts1.tv_sec * 1000 + ts1.tv_nsec / 1000000;
}

typedef unsigned long _uint32;

_uint32 aprime[200] = {
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
	37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
	79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
	131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
	181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
	239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
	293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
	359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
	421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
	479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
	557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
	613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
	673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
	743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
	821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
	881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
	953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019,
	1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087,
	1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
	1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229
};

const large_digit RSA_SIGN = large_digit(1) << (RSA_NBIT >> 1);
const large_digit RSA_GOOD = (RSA_SIGN >> 1) + 1;
const large_digit RSA_MASK = (RSA_SIGN - 1);

static void rand_product(large_digit &rnd)
{
	rnd.salt(RSA_NBIT);
	return;
}

large_digit mul_mod(const large_digit &a,
		const large_digit &b, const large_digit &n)
{
	return a * b % n;
}

large_digit expr_mod(const large_digit &x,
		const large_digit &r, const large_digit &n)
{
	int nbits;
	large_digit v = x;
	large_digit u = 1;

	nbits = r.nbits();
	for (int i = 0; i < nbits; i++) {
		if (r.bit(i))
		   	u = mul_mod (u, v, n);
		v = mul_mod (v, v, n);
	}

	return u;
}

large_digit edura(large_digit a, large_digit b)
{
	int delta;
	large_digit d;
	large_digit n, v, X, Y;
	large_digit dx, x, dy, y;

	x = 1, dx = 0, y = 1, dy = 0;

	do {
		if (!a.sign() || !b.sign()) {
			break;
		}

		delta = a.compare(b);
		if (delta == 0) {
			break;
		}

		if (delta < 0)	{
			n = b / a;
			dx += n * x;
			y += dy * n;
			b %= a;
			delta = -1;
		}

		if (b > 1)	{
			n = a / b;
			dy += n * y;
			x += dx * n;
			a %= b;
		}

		d = (a - 1) % b;
	} while (d.sign());

	v = (a - 1) / b;
	X = (x + v * dx);
	/* Y = (y * v + dy); */

	return X;
}

static bool rabin(const large_digit &ld)
{
	int k;
	int i, r;
	bool result = false;
	large_digit m, a, u;

	r = 0;
	m = ld - 1;
	while (m.bit(r++));
	m >>= (--r);

	for (k = 0; k < 5; k++) {
		rand_product(a);
		a %= (ld - 2);
		a += 2;

		u = expr_mod(a, m, ld);
		if (u == 1)
			continue;

		for (i = 0; i < r; i++) {
			if (u + 1 == ld)
				break;
			u = mul_mod (u, u, ld);
		}

		if (i == r) {
			goto failure;
		}
	}

#if 1
	for (i = 0; i < 200; i++) {
		if (ld <= aprime[i]) {
			break;
		}

		if (ld % aprime[i] == 0) {
			goto failure;
		}
	}
#endif

	result = true;

failure:
	return result;
}

static void prime_product(large_digit &prime)
{
	prime.salt(RSA_NBIT / 2);
	prime &= RSA_MASK;
	prime |= RSA_GOOD;

	while (!rabin(prime)) {
#if 0
		char buf[1024];
		printf("failure, retry: %s!\n", prime.write_digit(buf, 100));
#endif
		prime.salt(RSA_NBIT / 2);
		prime &= RSA_MASK;
		prime |= RSA_GOOD;
	}

	return;
}

static bool egcd(large_digit m, large_digit r)
{
	large_digit t;

	for ( ; ; ) {
		t = m % r;
		if (t.sign() == 0)
			return r != 1;

		m = r % t;
		if (m.sign() == 0)
			return t != 1;

		r = t % m;
		if (r.sign() == 0)
			return m != 1;
	}

	return false;
}

static void print_rsa_key(const large_digit &e,
	const large_digit &d, const large_digit &n)
{
	char ebuf[1024], dbuf[1024], nbuf[1024];

	printf("encrypt key: e = %s, n = %s\n", e.write_digit(ebuf, 1024), n.write_digit(nbuf, 1024));
	printf("decrypt key: d = %s, n = %s\n", d.write_digit(dbuf, 1024), nbuf);
	return;
}

int  main(void)
{
	large_digit t;
	large_digit i;
	large_digit shift;
	large_digit u, v, m;
	large_digit e, d, n;
	large_digit p, q, psi;

	srand(time(NULL));
	
#if 0
	large_digit d1, d2;
	d1.read_digit("48702C12C0FC3EC2456769127A09C444");
	d2.read_digit("BC72B98A8FE6392F");

	d1 % d2;
	return 0;
#endif

	DWORD keygen_start = GetTickCount();
	prime_product(p);
	prime_product(q);
	while (p == q) {
		fprintf(stderr, "p == q\n");
		prime_product(q);
	}

	n = p * q;
	psi = (p - 1) * (q - 1);

	char buf[1024];
	printf("p = %s\n", p.write_digit(buf, 1000));
	printf("q = %s\n", q.write_digit(buf, 1000));

	e = 65537;
	while (egcd(psi, e)) {
		rand_product(e);
		e %= psi;
	}

	d = edura(e, psi);
	print_rsa_key(e, d, n);
	DWORD keygen_finish = GetTickCount();
	printf("time use: %d\n", keygen_finish - keygen_start);
	getchar();

	i = n;
	shift = 1;
	int ij = 0, jj = 0;
	while (i != 0) {

		jj = 0;
		t = shift;
		while (t != 0) {
			rand_product(m);
			m &= (shift - 1);
			m |= shift;
			m |= 1;
			m %= n;

			DWORD crypt0 = GetTickCount();
			v = expr_mod(m, e, n);
			DWORD crypt1 = GetTickCount();
			u = expr_mod(v, d, n);
			DWORD crypt2 = GetTickCount();
			if (m != u) {
				char mbuf[1024], ubuf[1024], vbuf[1024];
				m.write_digit(mbuf, sizeof(mbuf));
				u.write_digit(ubuf, sizeof(ubuf));
				v.write_digit(vbuf, sizeof(vbuf));
				printf ("m = %s, u = %s, v = %s\n", mbuf, ubuf, vbuf);
				assert(0);
			}

			printf("i = %d, j = %d et = %d, dt = %d\n", ij, jj, crypt1 - crypt0, crypt2 - crypt1);
			t >>= 1;
			jj++;
		}

		shift <<= 1;
		i >>= 1;
		ij++;
	}

	return 0;
}
