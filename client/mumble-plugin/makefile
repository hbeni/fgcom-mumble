.PHONY : all all-debug plugin libs test clean clean-all debug-on
CC=g++
DEBUG=
override CFLAGS+=-I. -I./lib -pthread $(DEBUG)
SSLFLAGS+=-lssl -lcrypto -DSSLFLAGS

# get version
GITCOMMIT:=$(shell git log -1 --pretty=format:"%h")
GITDATE:=$(shell git log -1 --pretty=format:"%cd" --date=short)
VERSION_V:=$(shell grep -m1 FGCOM_VERSION_MAJOR fgcom-mumble.h |grep -E -o '[0-9]')
VERSION_M:=$(shell grep -m1 FGCOM_VERSION_MINOR fgcom-mumble.h |grep -E -o '[0-9]')
VERSION_P:=$(shell grep -m1 FGCOM_VERSION_PATCH fgcom-mumble.h |grep -E -o '[0-9]')
VERSION:=$(VERSION_V).$(VERSION_M).$(VERSION_P)


# Notice: Special calls
#
# `make DEBUG+="-DDEBUG"`                  enable debug code (add "-g3 -DDEBUG" for additional gdb symbols)
# `make CFLAGS+="-DNO_UPDATER" SSLFLAGS=`  skip auto-updater code
#

# FOR PRERELEASES: make always debug builds
ifneq (,$(findstring 0,$(VERSION_V)))
    DEBUG+=-g3 -DDEBUG
endif


# Compile all that stuff
all: plugin test clean

# DEBUG MODE
#   convinience invocation for debug build fpr GDB
#   -g3:     gdb debugging symbols
#   -DDEBUG: makes debug code active (prints internal state to stdout every sec)
all-debug:
	make DEBUG+="-g3 -DDEBUG" all

# make the plugin
plugin: libs
	$(CC) -shared -fPIC -o fgcom-mumble.so lib/radio_model.o lib/audio.o lib/io_plugin.o lib/io_UDPServer.o lib/io_UDPClient.o lib/garbage_collector.o fgcom-mumble.cpp $(SSLFLAGS) $(CFLAGS)

# make all the libs
libs:  lib/radio_model.o lib/audio.o lib/io_plugin.o lib/io_UDPServer.o lib/io_UDPClient.o lib/garbage_collector.o

%.o : %.cpp
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

# Compile tests and stuff
test: libs
	$(CC) -o test/geotest lib/radio_model.o test/geotest.cpp $(CFLAGS)
	$(CC) -o test/frqtest lib/radio_model.o test/frqtest.cpp $(CFLAGS)

# clean compile results
clean:
	rm -f *.o lib/*.o

# clean compile results and binarys
clean-all: clean
	rm -f test/geotest test/frqtest
	rm -f fgcom-mumble.so
	rm -f *.exe test/*.exe *.dll lib/*.dll



# Build all win64 stuff
#   apt-get install mingw-w64
all-win: plugin-win64 test-win64 clean

# build win64 test tools
test-win64:
	x86_64-w64-mingw32-g++-posix -o test/geotest.exe lib/radio_model.cpp test/geotest.cpp -static-libgcc -static-libstdc++ $(CFLAGS)
	x86_64-w64-mingw32-g++-posix -o test/frqtest.exe lib/radio_model.cpp test/frqtest.cpp -static-libgcc -static-libstdc++ $(CFLAGS)

# build win64 plugin-dll
plugin-win64: openssl-win
	x86_64-w64-mingw32-g++-posix -static -o fgcom-mumble.dll lib/io_plugin.cpp lib/radio_model.cpp lib/audio.cpp lib/io_UDPServer.cpp lib/io_UDPClient.cpp lib/garbage_collector.cpp fgcom-mumble.cpp --shared -static-libgcc -static-libstdc++ -DMINGW_WIN64 -Wl,-Bstatic -lpthread -lws2_32 $(SSLFLAGS) $(CFLAGS) -I./lib/openssl/include -L./lib/openssl/ -lcrypt32


# OpenSSL
# The sources are located under lib/openssl as git submodule, and supposed to point to the latest stable head
# Info on configure options: https://wiki.openssl.org/index.php/Compilation_and_Installation
openssl-win:
ifdef SSLFLAGS
	@echo "BUILD OpenSSL"
	git submodule init
	git submodule update
	cd lib/openssl/ && ./Configure mingw64 no-weak-ssl-ciphers no-ssl2 no-ssl3 no-idea no-dtls1 --cross-compile-prefix=x86_64-w64-mingw32- && make clean && make
	cp lib/openssl/libssl.dll.a lib/openssl/libssl.a        # so -lssl finds the correct lib
	cp lib/openssl/libcrypto.dll.a lib/openssl/libcrypto.a  # so -lcrypto finds the correct lib
endif


# Build release archives
release: clean-all plugin plugin-win64
	@echo GIT commit $(GITCOMMIT) from $(GITDATE), V$(VERSION)
	head -n 1 ../../README.md > releaseReadme.md
	@echo Version: $(VERSION) \($(GITCOMMIT) $(GITDATE)\) >> releaseReadme.md
	tail +2 ../../README.md >> releaseReadme.md
	
	# Linux + Windows combined
	mkdir fgcom-mumble-client-$(VERSION)
	mkdir fgcom-mumble-client-$(VERSION)/plugin
	rm -f fgcom-mumble-*.zip
	cp releaseReadme.md fgcom-mumble-client-$(VERSION)/README.md
	cp ../../LICENSE ../../README-de_DE.md ../../Readme.architecture.md ../plugin.spec.md fgcom-mumble-client-$(VERSION)/
	cp fgcom-mumble.so  fgcom-mumble-client-$(VERSION)/plugin
	cp fgcom-mumble.dll fgcom-mumble-client-$(VERSION)/plugin
	cp fgcom-mumble.ini fgcom-mumble-client-$(VERSION)/plugin
	cp -r ../fgfs/ fgcom-mumble-client-$(VERSION)
	zip -r fgcom-mumble-client-$(VERSION).zip fgcom-mumble-client-$(VERSION)
	rm -rf fgcom-mumble-client-$(VERSION)
	
	# Just a binary package for the mumble updater
	# Note: this ZIP may has a special format
	zip fgcom-mumble-client-binOnly-$(VERSION).zip fgcom-mumble.so fgcom-mumble.dll
	
	rm releaseReadme.md
	@echo "\nPluginrelease $(VERSION) built successfully:"
	@ls -alh *$(VERSION)*
	@md5sum *$(VERSION)*

showVer:
	@echo "GITCOMMIT:$(GITCOMMIT)"
	@echo "GITDATE:$(GITDATE)"
	@echo "VERSION:$(VERSION)"
