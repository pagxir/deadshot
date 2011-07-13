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

inline void store_copy(store_t *d, store_t *s, size_t l)
{
	memcpy(d, s, l * sizeof(*d));
	return;
}

inline void store_move(store_t *d, store_t *s, size_t l)
{
	memmove(d, s, l * sizeof(*d));
	return;
}

inline void store_clear(store_t *p, size_t l)
{
	memset(p, 0, l * sizeof(*p));
	return;
}

inline size_t len_strip(store_t *p, size_t l)
{
	store_t *e;

	e = p + l;
	while (e > p) {
		if (*--e)
			break;
		l--;
	}

	return l;
}

inline size_t bic_init(void)
{
	int bic = 0;
	int biv = RAND_MAX;

	while (biv > 0) {
		biv >>= 8;
		bic++;
	}

	return bic;
}

inline size_t bit_nlen(store_t d)
{
	size_t c = 0;
	size_t n = NBITHALF;

	while (n > 0) {
		store_t t = (d >> n);
		if (t != 0) {
			c += n;
			d = t;
		}
		n >>= 1;
	}

	return (c + 1);
}

inline store_t am_sum(store_t a,
		store_t b, store_t *sp)
{
	*sp = (a + b);
	return store_t(*sp < a);
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

int large_digit::sign(void) const
{
	int flag;
	flag = (m_flag & LDF_NEGATIVE);

	if (flag != 0)
		return -1;

	return m_nlen? 1: 0;
}

void large_digit::salt(size_t nbits)
{
	int salt0;
	size_t mc, rc;
	char *pmem = (char *)m_mem;
	static const int bic = bic_init();

	rc = 0;
	m_nlen = (nbits / NBITSTORE);
	m_nlen = IMIN(m_nlen, countof(m_mem));

	mc = m_nlen * NBITSTORE / 8;
	while (mc > 0) {
		if (rc == 0) {
			salt0 = rand();
			rc = bic;
		}

		*pmem++ = salt0;
		salt0 >>= 8;
		rc--; 
		mc--;
	}

	m_nlen = len_strip(m_pbuf, m_nlen);
	return;
}

int large_digit::bit(size_t index) const
{
	size_t bimask;
	size_t nstore;

	if (index < m_nlen * NBITSTORE) {
		bimask = BIMASK(index);
		nstore = NSTORE(index);
		return 0 != (m_pbuf[nstore] & bimask);
	}

	return false;
}

store_t large_digit::digit(size_t index) const
{
	int negf;

	if (index < m_nlen)
		return m_pbuf[index];

	negf = m_flag & LDF_NEGATIVE;
	return (negf? ~store_t(0): store_t(0));
}

store_t large_digit::am(store_t x, store_t *w, size_t j, size_t nlen) const
{
	size_t i = 0;
	store_t c = 0;
	store_t xh = HISTORE(x);
	store_t xl = LOSTORE(x);

	while (nlen-- > 0) {
		store_t mm, c1, c2, ll;
		store_t l = LOSTORE(m_pbuf[i]);
		store_t h = HISTORE(m_pbuf[i]);
		c1 = am_sum(xh * l, h * xl, &mm);
		c2 = am_sum(l * xl, RESTORE(mm), &l);
		c2 += am_sum(l, w[j], &ll);
		c2 += am_sum(c, ll, &w[j]);
		c = h * xh + c2 + HISTORE(mm) + RESTORE(c1);
		i++, j++;
	}

	return c;
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

size_t large_digit::nbits(void) const
{
	store_t digit0;

	if (m_nlen > 0) { 
		digit0 = digit(m_nlen - 1);
	   	return (m_nlen - 1) * NBITSTORE + bit_nlen(digit0);
	}

	return 0;
}

int large_digit::compare(const large_digit &use) const
{
	int i;
	int flag;
	store_t *digitl, *digitr;

	if (sign() != use.sign())
		return sign() - use.sign();

	if (m_nlen != use.m_nlen)
		return m_nlen - use.m_nlen;

	digitl = m_pbuf + m_nlen;
	digitr = use.m_pbuf + use.m_nlen;

	for (i = 0; i < m_nlen; i++)
		if (*--digitl != *--digitr)
			break;

	if (i == m_nlen)
		return 0;

	flag = (*digitl < *digitr);
	return flag? -1: 1;
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

/* multiply */
large_digit large_digit::operator * (const large_digit &use) const
{
	int i, nlen;
	large_digit retval;
	store_t *pbuf = retval.m_pbuf;

	i = m_nlen;
	nlen = i + use.m_nlen;

	while (--i >= 0)
		retval.m_pbuf[i] = 0;

	for (i = 0; i < use.m_nlen; i++)
		pbuf[i + m_nlen] = am(use.m_pbuf[i], pbuf, i, m_nlen);

	retval.m_nlen = len_strip(retval.m_pbuf, nlen);
	return retval;
}

large_digit large_digit::operator / (const large_digit &use) const
{
	int hibit1, hibit2;
	large_digit result, remainer(*this);

	if (m_nlen == 0)
		return result;

	if (use.m_nlen == 0)
		return result;

	hibit2 = use.nbits();

	do {
		hibit1 = remainer.nbits();

		if (hibit1 >= hibit2) {
			remainer.decrease(use, hibit1 - hibit2);
			result.increase(hibit1 - hibit2);
		}

		while (remainer.sign() < 0 && hibit1 > hibit2) {
			remainer.increase(use, --hibit1 - hibit2);
			result.decrease(hibit1 - hibit2);
		}

	} while (hibit1 > hibit2);

	if (remainer.sign() < 0) {
		remainer.increase(use, 0);
		result.decrease(0);
	}

	return result;
}

large_digit large_digit::operator % (const large_digit &use) const
{
	int hibit1, hibit2;
	large_digit result, remainer(*this);

	if (m_nlen == 0)
		return remainer;

	if (use.m_nlen == 0)
		return remainer;

	hibit2 = use.nbits();

	do {
		hibit1 = remainer.nbits();

		if (hibit1 >= hibit2)
			remainer.decrease(use, hibit1 - hibit2);

		while (remainer.sign() < 0 && hibit1 > hibit2)
			remainer.increase(use, --hibit1 - hibit2);

	} while (hibit1 > hibit2);

	if (remainer.sign() < 0)
		remainer.increase(use, 0);

	return remainer;
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
	if (sign() < 0)
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
