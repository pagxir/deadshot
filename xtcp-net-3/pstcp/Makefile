RM = rm
LDLIBS = -lws2_32
CFLAGS = -O2 -g
CXXFLAGS = -O2 -g
OBJECTS = rgnbuf.o event.o modules.o tcp_device.o \
		  tcp_input.o tcp_output.o tcp_timer.o \
		  tcp_usrreq.o timer.o platform.o
SRV_OBJ = server.o pstcp_channel.o pstcp_listen.o
CLT_OBJ = client.o tcp_listen.o tcp_channel.o
USRV_OBJ = server.o pstcp_listen.o pstcp_http.o

all: server.exe client.exe

server.exe: $(SRV_OBJ) $(OBJECTS) 
	$(CXX) $(LDFLAGS) $(SRV_OBJ) $(OBJECTS) $(LDLIBS) -o $@

client.exe: $(CLT_OBJ) $(OBJECTS)
	$(CXX) $(LDFLAGS) $(CLT_OBJ) $(OBJECTS) $(LDLIBS) -o $@

uhttpd.exe: $(USRV_OBJ) $(OBJECTS)
	$(CXX) $(LDFLAGS) $(USRV_OBJ) $(OBJECTS) $(LDLIBS) -o $@

clean:
	$(RM) $(OBJECTS) $(CLT_OBJ) $(SRV_OBJ) $(USRV_OBJ)

