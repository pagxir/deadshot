#include "stdafx.h"
#include <assert.h>

#include "large_digit.h"

#define muchbit(typ) (sizeof(typ) << 3)
#define countof(arr) (sizeof(arr) / sizeof(arr[0]))

void store_clear(store_t *p, size_t l)
{
	while (l-- > 0)
		*p++ = 0;
	return;
}

void store_copy(store_t *d, store_t *s, size_t l)
{
	while (l-- > 0)
		*d++ = *s++;
	return;
}

void store_move(store_t *d, store_t *s, size_t l)
{
	if (d < s) {
		store_copy(d, s, l);
		return;
	}

	d += l;
	s += l;
	if (d > s) {
		while (l-- > 0)
			*--d = *--s;
		return;
	}

	return;
}

large_digit::large_digit(void)
:m_flag(0)
{
	m_pbuf = m_mem;
	m_nlen = countof(m_mem);
	store_clear(m_mem, m_nlen);
}

large_digit::~large_digit()
{

}

store_t large_digit::value(void) const
{
	assert(m_nlen > 0);
	return *m_pbuf;
}

large_digit::large_digit(store_t value)
:m_flag(0)
{
   	m_pbuf = m_mem;
	m_nlen = countof(m_mem);

	store_clear(m_mem, m_nlen);
	m_pbuf[0] = value;
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
	return ((*this - use).m_flag & LDF_BORROW) == LDF_BORROW;
}

bool large_digit::operator > (const large_digit &use) const
{
	return ((use - *this).m_flag & LDF_BORROW) == LDF_BORROW;
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
	return ((use - *this).m_flag & LDF_ZERO) == LDF_ZERO;
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
	store_t sum;
	store_t signv;
	store_t carry;
	int i, min, signf;

	min = (use.m_nlen < m_nlen)? use.m_nlen: m_nlen;

	carry = 0;
	for (i = 0; i < min; i++) {
		sum = carry + m_pbuf[i];
		carry = (sum < carry);

		m_pbuf[i] = sum + use.m_pbuf[i];
		carry = (carry || (m_pbuf[i] < sum));
	}

	while (carry && i < m_nlen) {
		m_pbuf[i] = carry + m_pbuf[i];
		carry = (m_pbuf[i] < carry);
	}

	while (carry == 0 && i < use.m_nlen) {
		carry = (carry || use.m_pbuf[i++]);
	}
	
	signv = (m_pbuf[m_nlen - 1] << 1);
	signf = ((signv >> 1) == m_pbuf[m_nlen - 1]);
	m_flag = ((m_flag & ~LDF_SIGN) | (signf? 0: LDF_SIGN));
	m_flag = ((m_flag & ~LDF_CARRY) | (carry? LDF_CARRY: 0));
	return *this;
}

large_digit & large_digit::operator -= (const large_digit &use)
{
	store_t sum;
	store_t carry;
	store_t signv;
	int i, min, nzero, signf;

	min = (use.m_nlen < m_nlen)? use.m_nlen: m_nlen;

	nzero = 0;
	carry = 1;
	for (i = 0; i < min; i++) {
		sum = carry + m_pbuf[i];
		carry = (sum < carry);

		m_pbuf[i] = sum + store_t(~use.m_pbuf[i]);
		carry = (carry || (m_pbuf[i] < sum));
		nzero = (nzero || m_pbuf[i]);
	}

	while (carry && i < m_nlen) {
		sum = carry + m_pbuf[i];
		carry = (sum < carry);

		m_pbuf[i] = sum + store_t(~0l);
		carry = (carry || (m_pbuf[i] < sum));
		nzero = (nzero || m_pbuf[i]);
	}

	while (carry == 0 && i < use.m_nlen) {
		carry = (carry || ~use.m_pbuf[i++]);
	}

	signv = (m_pbuf[m_nlen - 1] << 1);
	signf = ((signv >> 1) == m_pbuf[m_nlen - 1]);
	m_flag = ((m_flag & ~LDF_SIGN) | (signf? 0: LDF_SIGN));
	m_flag = ((m_flag & ~LDF_ZERO) | (nzero? 0: LDF_ZERO));
	m_flag = ((m_flag & ~LDF_BORROW) | (carry? 0: LDF_BORROW));
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
	do {
		while (ld >= use) {
			*this += (large_digit(1) << shift);
			ld -= use;
			use <<= 1;
			shift ++;
		}
		
		use >>= 1;
		shift--;
	} while (shift >= 0);

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

#if 0
	do {
		while (*this >= use) {
			*this -= use;
			use <<= 1;
			shift ++;
		}
		
		use >>= 1;
		shift--;
	} while (shift >= 0);

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
		memset(m_pbuf, 0, m_nlen * sizeof(*m_pbuf));
		return *this;
	}

	store_move(m_pbuf, m_pbuf + shift / muchbit(*m_pbuf),
		   	m_nlen - shift / muchbit(*m_pbuf));
	store_clear(m_pbuf + m_nlen - shift / muchbit(*m_pbuf),
		   	shift / muchbit(*m_pbuf));
	shift %= muchbit(*m_pbuf);

	if (shift != 0) {
		i = m_nlen;
		bitvalues = 0;
		while (i-- > 0) {
			keep = m_pbuf[i];
			m_pbuf[i] = (bitvalues | (m_pbuf[i] >> shift));
			bitvalues = (keep << (muchbit(keep) - shift));
		}
	}

	return *this;
}

large_digit &large_digit::operator <<= (long shift)
{
	int i, index;
	store_t keep;
	store_t bitvalues;

	if (shift >= m_nlen * muchbit(*m_pbuf)) {
		m_flag |= (*this != 0? LDF_CARRY: 0);
		return *this;
	}

	for (i = 0; i < shift / muchbit(*m_pbuf); i++) {
		index = m_nlen + i - shift / muchbit(*m_pbuf);
		if (m_pbuf[index] != 0) {
			m_flag |= LDF_CARRY;
			break;
		}
	}

	store_move(m_pbuf + shift / muchbit(*m_pbuf),
		   	m_pbuf, m_nlen - shift / muchbit(*m_pbuf));
	store_clear(m_pbuf, shift / muchbit(*m_pbuf));
	shift %= muchbit(*m_pbuf);

	if (shift != 0) {
		bitvalues = 0;
		for (i = 0; i < m_nlen; i++) {
			keep = m_pbuf[i];
			m_pbuf[i] = (bitvalues | (keep << shift));
			bitvalues = (keep >> (muchbit(*m_pbuf) - shift));
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

void write_large_digit(large_digit &ld, char *outp)
{
	char t;
	char *keep = outp;

	while (ld != 0) {
		*outp++ = (ld % 10).value() + '0';
		ld /= 10;
	}
	*outp = 0;

	while (keep < outp) {
		t = *keep;
		*keep++ = *--outp;
		*outp = t;
	}
}

