#ifndef _LARGE_DIGIT_
#define _LARGE_DIGIT_

#define LDF_ZERO        1
#define LDF_CARRY       2
#define LDF_BORROW      4
#define LDF_NEGATIVE 0x08
#define LDF_OWERFLOW 0x10

#define NBITSTORE      (sizeof(store_t) * 8)
#define NSTORE(i)      ((i) / NBITSTORE)
#define BSTORE(i)      ((i) % NBITSTORE)
#define BIMASK(i)      ((1) << BSTORE(i))

#define NBITHALF           (NBITSTORE >> 1)
#define HALFMASK           (BIMASK(NBITHALF) - (1))
#define HISTORE(store)     ((store) >> NBITHALF)
#define RESTORE(store)     ((store) << NBITHALF)
#define LOSTORE(store)     ((store) & HALFMASK)

typedef unsigned long store_t;

class large_digit
{
	private:
		int m_nlen;
		int m_flag;
		store_t m_mem[32 + 1];
		store_t *m_pbuf;

	public:
		void salt(void);
		bool bit(size_t index) const;
		bool operator !(void) const;
		store_t digit(size_t index) const;
		void read_digit(const char *str);
		char *write_digit(char *str, size_t len) const;

	public:
		large_digit(void);
		~large_digit(void);
		large_digit(store_t value);

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

	private:
		store_t am(store_t x, store_t *w, size_t j, size_t nlen) const;
	
		void increase(const large_digit &ld, long shift);
		void increase(long shift);

		void decrease(const large_digit &ld, long shift);
		void decrease(long shift);
};

#endif

