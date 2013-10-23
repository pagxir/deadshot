#CXX = cl
#LD  = link
#CRT = C:\Applications\VC2008EE\WDK\Include\crt
#STL = C:\Applications\VC2008EE\WDK\Include\api\crt\stl60
#CFLAGS =  /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "__WIN32__" \
		  /O2 /Oi /Os /GT /GL /FD /MT /GS- /GR-  /c /Zi /TP /Gy /TP /I $(CRT) /I $(STL) 
#CXXFLAGS = /Zi /c /FoRelease/ /FdRelease/ $(CFLAGS) 
#VC80LIB = C:\Applications\VC2008EE\WDK\Lib
#CRTLIB = C:\Applications\VC2008EE\WDK\Lib
#LDFLAGS  = /subsystem:console /nodefaultlib /libpath:$(VC80LIB) /libpath:$(CRTLIB) /machine:I386 /pdb:socks5m.pdb /debug /incremental:no
#LDLIBS   = ws2_32.lib mswsock.lib advapi32.lib kernel32.lib msvcrt.lib msvcrt_winxp.obj libcpmt.lib
LDLIBS  = -lws2_32 -lmswsock -ladvapi32 -lkernel32

VPATH += Release

.PHONY: all
all: socks5m.exe
#socks5p.exe: Release socks5p.o
#	$(CXX) $(LDFLAGS) socks5p.o -o socks5p.exe $(LDLIBS)

socks5m.exe: Release Server.o Network.o
	$(CXX) $(LDFLAGS) Server.o Network.o -o socks5m.exe $(LDLIBS)

Release:
	mkdir Release

#.SUFFIXES: .c .cpp .obj
#.c.obj:
#	$(CXX) $(CXXFLAGS) $^
#.cpp.obj:
#	$(CXX) $(CXXFLAGS) $^

