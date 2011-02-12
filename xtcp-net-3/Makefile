CC = gcc
OBJECTS = tcp_output.o tcp_input.o rgnbuf.o \
		  dtype.o xtcp.o pthread.o tcp_usrreq.o tcp_timer.o
LDLIBS = -lws2_32
CFLAGS = -g -I.
CXXFLAGS = -g -I.

all: demo_client demo_server
demo_client: demo_client.o $(OBJECTS)
	$(CC) -o demo_client $(LDFLAGS) $(OBJECTS) demo_client.o $(LDLIBS)

demo_server: demo_server.o $(OBJECTS)
	$(CC) -o demo_server $(LDFLAGS) $(OBJECTS) demo_server.o $(LDLIBS)

clean:
	rm -f $(OBJECTS) demo_client.o demo_server.o demo_client demo_server
