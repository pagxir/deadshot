CC = g++
RM = rm
CFLAGS = -DARCH_IS_LITTLE_ENDIAN  -g -D__stdcall="" -m32 -g
CXXFLAGS = $(CFLAGS)
LDFLAGS = -lm -m32
OBJECTS = pertld.o peimg_file.o MSVCRT.o buildin.o KERNEL32.o
#LDFLAGS = -mwindows -lm -L. -lgdi32 -lws2_32

main: $(OBJECTS)
	$(CC) $(LDFLAGS) -o main $(OBJECTS) $(LDLIBS)

clean:
	$(RM) -f *.o
