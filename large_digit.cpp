#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "large_digit.h"

#define muchbit(typ) (sizeof(typ) << 3)
#define countof(arr) (sizeof(arr) / sizeof(arr[0]))
#define IMAX(a, b) ((a) < (b)? (b): (a))
#define IMIN(a, b) ((a) < (b)? (a): (b))

void store_clear(store_t *p, size_t l)
{
	memset(p, 0, l * sizeof(*p));
	return;
}

void store_copy(store_t *d, store_t *s, size_t l)
{
	memcpy(d, s, l * sizeof(*d));
	return;
}

void store_move(store_t *d, store_t *s, size_t l)
{
	memmove(d, s, l * sizeof(*d));
	return;
}

large_digit::large_digit(void)
:m_flag(0)
{
	m_nlen = 0;
	m_pbuf = m_mem;
}

large_digit::~large_digit()
{

}

void large_digit::salt(void)
{
	int i;
	store_t salt0 = 0;

	m_nlen = 0;
	i = countof(m_mem);
	while (i > 0) {
		salt0 = ((rand() << 16) | rand());
		if (salt0 != 0)
			break;
		m_pbuf[--i] = salt0;
	}

	if (salt0 == 0) {
		assert(i == 0);
		return;
	}

	m_nlen = i--;
	m_pbuf[i] = salt0;

	while (i > 0) {
		salt0 = ((rand() << 16) | rand());
		m_pbuf[--i] = salt0;
	}

	return;
}

bool large_digit::bit(long idx) const
{
	size_t byof, biof;

	if (size_t(idx) < m_nlen * muchbit(store_t)) {
		byof = idx / muchbit(store_t);
		biof = idx % muchbit(store_t);
		return (m_pbuf[byof] & (1 << biof))? true: false;
	}

	return false;
}

store_t large_digit::digit(int idx) const
{
	if (idx < m_nlen)
		return m_pbuf[idx];

	if (m_flag & LDF_NEGATIVE)
		return ~store_t(0);

	return store_t(0);
}

large_digit::large_digit(store_t value)
:m_flag(0)
{
	m_nlen = 0;
	m_pbuf = m_mem;

	if (value != 0) {
		m_pbuf[0] = value;
		m_nlen = 1;
	}
}

large_digit::large_digit(const large_digit &use)
{
	m_pbuf = m_mem;
	m_flag = use.m_flag;
	m_nlen = use.m_nlen;
	if (m_nlen > countof(m_mem))
		m_nlen = countof(m_mem);
	store_copy(m_pbuf, use.m_pbuf, m_nlen);
}

large_digit & large_digit::operator = (const large_digit &use)
{
	m_pbuf = m_mem;
	m_flag = use.m_flag;
	m_nlen = use.m_nlen;
	if (m_nlen > countof(m_mem))
		m_nlen = countof(m_mem);
	store_copy(m_pbuf, use.m_pbuf, m_nlen);
	return *this;
}

large_digit large_digit::operator + (const large_digit &use) const
{
	return large_digit(*this) += use;
}

large_digit large_digit::operator - (const large_digit &use) const
{
	return large_digit(*this) -= use;
}

large_digit large_digit::operator * (const large_digit &use) const
{
	return large_digit(*this) *= use;
}

large_digit large_digit::operator / (const large_digit &use) const
{
	return large_digit(*this) /= use;
}

large_digit large_digit::operator % (const large_digit &use) const
{
	return large_digit(*this) %= use;
}

bool large_digit::operator < (const large_digit &use) const
{
	return ((*this - use).m_flag & LDF_NEGATIVE) == LDF_NEGATIVE;
}

bool large_digit::operator > (const large_digit &use) const
{
	return ((use - *this).m_flag & LDF_NEGATIVE) == LDF_NEGATIVE;
}

bool large_digit::operator <= (const large_digit &use) const
{
	return !(*this > use);
}

bool large_digit::operator >= (const large_digit &use) const
{
	return !(*this < use);
}

bool large_digit::operator == (const large_digit &use) const
{
	return (use - *this).m_nlen == 0;
}

bool large_digit::operator != (const large_digit &use) const
{
	return !(use == *this);
}

large_digit large_digit::operator << (long shift) const
{
	return large_digit(*this) <<= shift;
}

large_digit large_digit::operator >> (long shift) const
{
	return large_digit(*this) >>= shift;
}

large_digit & large_digit::operator += (const large_digit &use)
{
	int i;
	int nlen;
	store_t sum;
	store_t carry;
	store_t hidigit;

	nlen = IMAX(m_nlen, use.m_nlen);

	carry = 0;
	assert(nlen <= countof(m_mem));
	for (i = 0; i < nlen; i++) {
		sum = carry + digit(i);
		carry = (sum < carry);

		m_pbuf[i] = sum + use.digit(i);
		carry |= (m_pbuf[i] < sum);
	}

	hidigit = digit(nlen) + use.digit(nlen) + carry;

	m_flag = 0;
	switch (hidigit) {
		case ~store_t(0):
			m_flag |= LDF_NEGATIVE;
			break;

		case store_t(0):
			break;

		default:
			if (nlen < countof(m_mem))
				m_pbuf[nlen++] = hidigit;
			else
				m_flag |= LDF_CARRY;
			break;
	}

	if (m_flag & LDF_NEGATIVE) {
	   	while (nlen > 0 && 
				!~m_pbuf[nlen - 1])
		   	nlen--;
	} else {
	   	while (nlen > 0 && 
				!m_pbuf[nlen - 1])
		   	nlen--;
	}

	m_nlen = nlen;
	return *this;
}

large_digit & large_digit::operator -= (const large_digit &use)
{
	int i;
	int nlen;
	store_t sum;
	store_t carry;
	store_t hidigit;

	nlen = IMAX(m_nlen, use.m_nlen);

	carry = 1;
	assert(nlen <= countof(m_mem));
	for (i = 0; i < nlen; i++) {
		sum = carry + digit(i);
		carry = (sum < carry);

		m_pbuf[i] = sum + ~use.digit(i);
		carry |= (m_pbuf[i] < sum);
	}

	hidigit = digit(nlen) + ~use.digit(nlen) + carry;

	m_flag = 0;
	switch (hidigit) {
		case ~store_t(0):
			m_flag |= LDF_NEGATIVE;
			break;

		case store_t(0):
			m_flag |= LDF_BORROW;
			break;

		default:
			if (nlen < countof(m_mem))
				m_pbuf[nlen++] = hidigit;
			else
				m_flag |= LDF_CARRY;
			break;
	}

	if (m_flag & LDF_NEGATIVE) {
	   	while (nlen > 0 && 
				!~m_pbuf[nlen - 1])
		   	nlen--;
	} else {
	   	while (nlen > 0 && 
				!m_pbuf[nlen - 1])
		   	nlen--;
	}

	m_nlen = nlen;
	return *this;
}

large_digit & large_digit::operator *= (const large_digit &use)
{
	int i, j, value;
	large_digit ld(*this);

	*this = 0;
	for (i = 0; i < use.m_nlen; i++) {
		if (use.m_pbuf[i] == 0) {
			ld <<= muchbit(m_pbuf[i]);
			continue;
		}

		value = use.m_pbuf[i];
		for (j = 0; j < muchbit(m_pbuf[i]); j++) {
			if (value & 1ul)
				*this += ld;
			value >>= 1;
			ld <<= 1;
		}
	}

	return *this;
}

large_digit & large_digit::operator /= (const large_digit &arg)
{
	int shift;
	large_digit ld(*this);
	large_digit use(arg);

	shift = 0;
	*this = 0;
	assert(arg != 0);

#if 1

	while (use <= ld) {
		*this += (large_digit(1) << shift);
		ld -= use;
		use <<= 1;
		shift ++;
	}

	while (shift > 0) {
		use >>= 1;
		shift--;
		if (use <= ld) {
			*this += (large_digit(1) << shift);
			ld -= use;
		}
	}

#else

	do {
		*this += (large_digit(1) << shift);
		ld -= use;

		while (ld.m_flag & LDF_SIGN) {
			if (--shift < 0) {
				*this -= 1;
				break;
			}

			*this -= (large_digit(1) << shift);
			use >>= 1;
			ld += use;
		}

		use <<= 1;
		shift++;
	} while (shift > 0);
#endif

	return *this;
}

large_digit & large_digit::operator %= (const large_digit &arg)
{
	int shift;
	large_digit use(arg);

	shift = 0;
	assert(arg != 0);

#if 1

	while (*this >= use) {
		if (use == 0)
			*(char *)0 = 0;
		*this -= use;
		use <<= 1;
		shift ++;
	}

	while (shift > 0) {
		use >>= 1;
		shift--;
		if (*this >= use)
			*this -= use;
	}

#else

	do {
		*this -= use;

		while (this->m_flag & LDF_SIGN) {
			if (--shift < 0) {
				*this += use;
				break;
			}

			use >>= 1;
			*this += use;
		}

		use <<= 1;
		shift++;
	} while (shift > 0);
#endif
	return *this;
}

/* how about signed large_digit */
large_digit &large_digit::operator >>= (long shift)
{
	int i;
	store_t keep;
	store_t bitvalues;

	if (shift >= m_nlen * muchbit(*m_pbuf)) {
		m_nlen = 0;
		return *this;
	}

	store_move(m_pbuf, m_pbuf + shift / muchbit(*m_pbuf),
			m_nlen - shift / muchbit(*m_pbuf));
	store_clear(m_pbuf + m_nlen - shift / muchbit(*m_pbuf),
			shift / muchbit(*m_pbuf));
	m_nlen -= shift / muchbit(*m_pbuf);
	shift %= muchbit(*m_pbuf);

	if (shift != 0) {
		i = m_nlen;
		bitvalues = 0;
		m_nlen = 0;
		while (i-- > 0) {
			keep = m_pbuf[i];
			m_pbuf[i] = (bitvalues | (m_pbuf[i] >> shift));
			if (m_pbuf[i] != 0)
				m_nlen = m_nlen < i + 1? i + 1: m_nlen;
			bitvalues = (keep << (muchbit(keep) - shift));
		}
	}

	return *this;
}

large_digit &large_digit::operator &= (const large_digit &use)
{
	int i;
	int min;

	min = (use.m_nlen < m_nlen)? use.m_nlen: m_nlen;
	m_nlen = 0;
	for (i = 0; i < min; i++) {
		m_pbuf[i] &= use.m_pbuf[i];
		if (m_pbuf[i] != 0)
			m_nlen = i + 1;
	}

	return *this;
}

large_digit &large_digit::operator |= (const large_digit &use)
{
	int i;
	int min;

	min = (use.m_nlen < m_nlen)? use.m_nlen: m_nlen;
	for (i = 0; i < min; i++)
		m_pbuf[i] |= use.m_pbuf[i];

	while (i < use.m_nlen) {
		m_pbuf[i] = use.m_pbuf[i];
		i++;
	}

	m_nlen = (m_nlen < i? i: m_nlen);
	return *this;
}

large_digit &large_digit::operator <<= (long shift)
{
	int i, index;
	store_t keep;
	store_t bitvalues;

	if (shift >=  muchbit(m_mem)) {
		fprintf(stderr, "over flow\n");
		m_nlen = 0;
		return *this;
	}

	m_nlen += shift / muchbit(*m_pbuf);
	m_nlen = (m_nlen < countof(m_mem)? m_nlen: countof(m_mem));
	store_move(m_pbuf + shift / muchbit(*m_pbuf),
			m_pbuf, m_nlen - shift / muchbit(*m_pbuf));
	store_clear(m_pbuf, shift / muchbit(*m_pbuf));
	shift %= muchbit(*m_pbuf);

	if (shift != 0) {
		int savelen = m_nlen;
		m_nlen = 0;
		bitvalues = 0;
		for (i = 0; i < savelen; i++) {
			keep = m_pbuf[i];
			m_pbuf[i] = (bitvalues | (keep << shift));
			if (m_pbuf[i] != 0)
				m_nlen = (i + 1);
			bitvalues = (keep >> (muchbit(*m_pbuf) - shift));
		}

		if (bitvalues > 0 && i < countof(m_mem)) {
			m_pbuf[i] = (bitvalues);
			if (m_pbuf[i] != 0)
				m_nlen = (i + 1);
		}
	}

	return *this;
}

void read_large_digit(large_digit &ld, const char *inp)
{
	while (*inp) {
		if (isdigit(*inp)) {
			ld *= 10;
			ld += (*inp - '0');
		}
		inp ++;
	}
}

void write_large_digit(large_digit ld, char *outp)
{
	char t;
	char *keep = outp;
	static char _ch_map[] = "0123456789ABCDEF";

	while (ld != 0) {
		*outp++ = _ch_map[ld.digit(0) & 0xF];
		ld >>= 4;
	}
	*outp = 0;

	while (keep < outp) {
		t = *keep;
		*keep++ = *--outp;
		*outp = t;
	}
}

