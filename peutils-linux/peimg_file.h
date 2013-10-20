
class PEFileImage: public PEImage {
	public:
		PEFileImage(const char * path);
		~PEFileImage();

	public:
		int IsValid() { return m_hFile != -1; }
		ssize_t pread(void * buf, size_t size, size_t off);

	private:
		int m_hFile;
};


