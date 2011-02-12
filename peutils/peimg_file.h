
class PEFileImage: public PEImage {
	public:
		PEFileImage(const char * path);
		~PEFileImage();

	public:
		BOOL IsValid() { return m_hFile != INVALID_HANDLE_VALUE; }
		ssize_t pread(void * buf, size_t size, size_t off);

	private:
		HANDLE m_hFile;
};


