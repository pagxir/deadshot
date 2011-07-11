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
	int salt0;
	int mc, rc, bic;
	int biv = RAND_MAX;
	char *pmem = (char *)m_mem;

	rc = bic = 0;
	while (biv > 0) {
		biv >>= 8;
		bic++;
	}

	mc = sizeof(m_mem);
	while (mc > 0) {
		if (rc == 0) {
			salt0 = rand();
			rc = bic;
		}

		*pmem++ = salt0;
		salt0 >>= 8;
		rc--; mc--;
	}

	m_nlen = countof(m_mem);
	while (m_nlen > 0 && 
		!m_pbuf[m_nlen - 1])
		m_nlen--;

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
	char buf[1024];
	store_t value;
	int i, j, shift;
	large_digit result = 0;

	shift = 0;
	for (i = 0; i < m_nlen; i++) {
		if (m_pbuf[i] == store_t(0)) {
			shift += muchbit(store_t);
			continue;
		}

		value = m_pbuf[i];
		for (j = 0; j < muchbit(store_t); j++) {
			if (value & 1ul) {
				result.increase(use, shift);
			}
			value >>= 1;
			shift++;
		}
	}

	return result;
}

large_digit large_digit::operator / (const large_digit &use) const
{
	int shift;
	large_digit result;
	large_digit remainer(*this);

	shift = 0;
	do {
		remainer.decrease(use, shift);
		result.increase(shift);
		if (remainer.m_flag & LDF_NEGATIVE)
			break;
		shift++;
	} while (shift > 0);

	while (shift > 0) {
		shift--;
		if (remainer.m_flag & LDF_NEGATIVE) {
			remainer.increase(use, shift);
			result.decrease(shift);
		} else {
			remainer.decrease(use, shift);
			result.increase(shift);
		}
	}

	if (remainer.m_flag & LDF_NEGATIVE) {
		remainer.increase(use, 0);
		result.decrease(0);
	}

	return result;
}

large_digit large_digit::operator % (const large_digit &use) const
{
	int shift;
	large_digit remainer(*this);

	shift = 0;
	do {
		remainer.decrease(use, shift);
		if (remainer.m_flag & LDF_NEGATIVE)
			break;
		shift++;
	} while (shift > 0);

	while (shift > 0) {
		shift--;
		if (remainer.m_flag & LDF_NEGATIVE) {
			remainer.increase(use, shift);
		} else {
			remainer.decrease(use, shift);
		}
	}

	if (remainer.m_flag & LDF_NEGATIVE)
		remainer.increase(use, 0);

	assert(remainer < use);
	return remainer;
}

bool large_digit::operator !(void) const
{
	if (m_flag & LDF_NEGATIVE)
		return false;

	return !m_nlen;
}

bool large_digit::operator < (const large_digit &use) const
{
	int flag = (*this - use).m_flag;
	return (flag & LDF_NEGATIVE) == LDF_NEGATIVE;
}

bool large_digit::operator > (const large_digit &use) const
{
	int flag = (use - *this).m_flag;
	return (flag & LDF_NEGATIVE) == LDF_NEGATIVE;
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
	int flag = (use - *this).m_flag;
	return (flag & LDF_ZERO) == LDF_ZERO;
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
		m_flag |= (nlen? 0: LDF_ZERO);
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
		m_flag |= (nlen? 0: LDF_ZERO);
	}

	m_nlen = nlen;
	return *this;
}

large_digit & large_digit::operator *= (const large_digit &use)
{
	large_digit ld = (*this * use);
	*this = ld;
	return *this;
}

large_digit & large_digit::operator /= (const large_digit &arg)
{
	*this = (*this / arg);
	return *this;
}

large_digit & large_digit::operator %= (const large_digit &arg)
{
	*this = (*this % arg);
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
	int i;
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

void large_digit::read_digit(const char *inp)
{
	large_digit &ld(*this);

	while (*inp) {
		if (isdigit(*inp)) {
			ld *= 10;
			ld += (*inp - '0');
		}
		inp ++;
	}
}

char *large_digit::write_digit(char *outp, size_t len) const
{
	int i;
	char *keep = outp;
	const large_digit &ld = *this;

	int count = sprintf(outp, "[%s] ", m_flag & LDF_NEGATIVE? "-": "+");
	outp += count;

	for (i = ld.m_nlen; i-- > 0; ) {
		int count = sprintf(outp, "%0*lX", sizeof(store_t) * 2, ld.digit(i));
		outp += count;		
	}

	return keep;
}

void large_digit::increase(const large_digit &ld, long shift)
{
	int i;
	int off;
	int nlen;
	store_t sum;
	store_t carry;
	store_t hidigit;
	store_t uval, digit1, digit2;
	store_t bitval, cntval, keepval;

	bitval = shift % muchbit(store_t);
	cntval = shift / muchbit(store_t);

	nlen = IMAX(m_nlen, cntval + ld.m_nlen + (bitval + muchbit(store_t) - 1) / muchbit(store_t));

	off = 0;
	carry = 0;
	keepval = 0;
	if (nlen > countof(m_mem)) {
		//printf("warn: %d\n", nlen);
		nlen = countof(m_mem);
	}

	for (i = cntval; i < nlen; i++) {
		sum = carry + digit(i);
		carry = (sum < carry);

		digit2 = (ld.digit(off) << bitval);
		digit1 = (bitval? (keepval >> (muchbit(store_t) - bitval)): 0);
		
		uval = sum + (digit1 | digit2);
		keepval = bitval? ld.digit(off): 0;
		carry |= (uval < sum);

		m_pbuf[i] = uval;
		off++;
	}

	digit2 = (ld.digit(off) << bitval);
	digit1 = (bitval? (keepval >> (muchbit(store_t) - bitval)): 0);
	hidigit = digit(nlen) + carry + (digit2 | digit1);

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
		m_flag |= (nlen? 0: LDF_ZERO);
	}

	m_nlen = nlen;
}

void large_digit::increase(long shift)
{
	int i;
	int nlen;
	store_t sum;
	store_t carry;
	store_t hidigit;
	store_t bitval, cntval, keep;

	bitval = shift % muchbit(store_t);
	cntval = shift / muchbit(store_t);

	nlen = IMAX(m_nlen, cntval + (bitval > 0));

	keep = (1ul << bitval);
	if (nlen > countof(m_mem))
		nlen = countof(m_mem);

	carry = 0;
	for (i = cntval; i < nlen; i++) {
		sum = carry + digit(i);
		carry = (sum < carry);

		m_pbuf[i] = sum + keep;
		carry = (m_pbuf[i] < sum);

		keep = 0;
	}

	hidigit = digit(nlen) + carry + keep;

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
		m_flag |= (nlen? 0: LDF_ZERO);
	}

	m_nlen = nlen;
}

void large_digit::decrease(const large_digit &ld, long shift)
{
	int i;
	int off;
	int nlen;
	store_t sum;
	store_t carry;
	store_t hidigit;
	store_t uval, digit1, digit2;
	store_t bitval, cntval, keepval;

	bitval = shift % muchbit(store_t);
	cntval = shift / muchbit(store_t);

	nlen = IMAX(m_nlen, cntval + ld.m_nlen + (bitval + muchbit(store_t) - 1) / muchbit(store_t));

	off = 0;
	carry = 1;
	keepval = 0;
	if (nlen > countof(m_mem)) {
		//printf("warn: %d\n", nlen);
		nlen = countof(m_mem);
	}
	
	for (i = cntval; i < nlen; i++) {
		sum = carry + digit(i);
		carry = (sum < carry);

		digit2 = (ld.digit(off) << bitval);
		digit1 = (bitval? (keepval >> (muchbit(store_t) - bitval)): 0);
		
		uval = ~(digit1 | digit2);
		uval = sum + uval;
		keepval = bitval? ld.digit(off): 0;
		carry |= (uval < sum);

		m_pbuf[i] = uval;
		off++;
	}

	digit2 = (ld.digit(off) << bitval);
	digit1 = (bitval? (keepval >> (muchbit(store_t) - bitval)): 0);
	hidigit = digit(nlen) + carry + ~(digit2 | digit1);

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
		m_flag |= (nlen? 0: LDF_ZERO);
	}

	m_nlen = nlen;
}

void large_digit::decrease(long shift)
{
	int i;
	int nlen;
	store_t sum;
	store_t carry;
	store_t hidigit;
	store_t bitval, cntval, keep;

	bitval = shift % muchbit(store_t);
	cntval = shift / muchbit(store_t);

	nlen = IMAX(m_nlen, cntval + (bitval > 0));

	assert(nlen <= countof(m_mem));
	keep = (1ul << bitval);

	carry = 1;
	for (i = cntval; i < nlen; i++) {
		sum = carry + digit(i);
		carry = (sum < carry);

		m_pbuf[i] = sum + ~keep;
		carry |= (m_pbuf[i] < sum);

		keep = 0;
	}

	hidigit = digit(nlen) + carry + ~keep;

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
		m_flag |= (nlen? 0: LDF_ZERO);
	}

	m_nlen = nlen;
}
