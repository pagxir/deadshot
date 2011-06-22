#ifndef _LARGE_DIGIT_
#define _LARGE_DIGIT_

#define LDF_ZERO        1
#define LDF_SIGN        2
#define LDF_CARRY       4
#define LDF_BORROW      8
#define LDF_OWERFLOW 0x10

typedef unsigned long store_t;

class large_digit {
	private:
		int m_nlen;
		int m_flag;
		store_t m_mem[16 + 1];
		store_t *m_pbuf;

	public:
		void salt(void);
		bool bit(long idx) const;
		store_t value(void) const;
		large_digit(store_t value);

	public:
		large_digit(void);
		~large_digit(void);

	public:
		large_digit &operator |= (const large_digit &ld);
		large_digit &operator &= (const large_digit &ld);

	public:
		large_digit(const large_digit &use);
		large_digit &operator >>= (long shift);
		large_digit &operator <<= (long shift);
		large_digit operator >> (long shift) const;
		large_digit operator << (long shift) const;
		large_digit &operator = (const large_digit &use);

	public:
		bool operator < (const large_digit &use) const;
		bool operator > (const large_digit &use) const;
		bool operator != (const large_digit &use) const;
		bool operator <= (const large_digit &use) const;
		bool operator >= (const large_digit &use) const;
		bool operator == (const large_digit &use) const;

	public:
		large_digit operator + (const large_digit &use) const;
		large_digit operator - (const large_digit &use) const;
		large_digit operator * (const large_digit &use) const;
		large_digit operator / (const large_digit &use) const;
		large_digit operator % (const large_digit &use) const;

	public:
		large_digit &operator += (const large_digit &use);
		large_digit &operator -= (const large_digit &use);
		large_digit &operator *= (const large_digit &use);
		large_digit &operator /= (const large_digit &use);
		large_digit &operator %= (const large_digit &use);
};

void read_large_digit(large_digit &ld, const char *buf);
void write_large_digit(large_digit ld, char *outp);

#endif

