CC = g++
RM = rm
CFLAGS = -DARCH_IS_LITTLE_ENDIAN  -g
CXXFLAGS = -g
LDFLAGS = -lm -lkernel32
OBJECTS = pertld.o peimg_file.o
#LDFLAGS = -mwindows -lm -L. -lgdi32 -lws2_32

main: $(OBJECTS)
	$(CC) $(LDFLAGS) -o main $(OBJECTS) $(LDLIBS)

clean:
	$(RM) -f *.o
