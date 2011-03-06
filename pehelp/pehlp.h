void *peMapImage(char* image);
void *peaux_LoadLibrary(const char *path);
void *peaux_GetProcAddress(void *hModule, const char *fName);
void *peaux_GetEntryPoint(void *hModule);
void  peaux_FreeLibrary(void *path);
