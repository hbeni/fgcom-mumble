.PHONY : all debug all-debug plugin-debug plugin libs test tools clean clean-all debug-on
CC=g++
DEBUG=
THREADS_UNIX=-pthread
THREADS_WIN=-Wl,-Bstatic -lstdc++ -lpthread -lws2_32
override CFLAGS+=-Wall -O3 -I. -I./lib $(DEBUG)
override CFLAGS_WIN+=-Wl,--subsystem,windows -static-libgcc -static-libstdc++ $(CFLAGS)
SSLFLAGS+=-lssl -lcrypto -DSSLFLAGS
SSLFLAGS_WIN+=-I./lib/openssl/include/ -L./lib/openssl/ -static -lssl -lcrypto -lws2_32 -lcrypt32 -DSSLFLAGS -D_WIN32
# Note on flags: -D_WIN32 is needed by httplib on Windows

lib_OBJS := lib/radio_model.o lib/audio.o lib/io_plugin.o lib/io_UDPServer.o lib/io_UDPClient.o lib/garbage_collector.o

# Notice: Special calls
#
# `make DEBUG+="-DDEBUG"`                  enable debug code (use `make DEBUG+="-g3 -DDEBUG -Og"` for additional gdb symbols)
# `make CFLAGS+="-DNO_UPDATER" SSLFLAGS=`  skip auto-updater code, and do not link against OpenSSL
#  More CFLAGS: -DNO_UDPCLIENT             no RDF data sending thread
#               -DNO_UDPSERVER             no UDP server thread
#               -DNO_NOTIFY                no pluginIO notification thread
#               -DNO_GC                    no garbage collector thread
#               -DNO_CFG                   no config file parsing
#               -DNO_COMMENT               no mumble GUI comment adjustments
# `make ... outname=<name> ...`            change name of resulting binary lib
# `make ... mingwprefix=<...>`             Change mingw prefix; CC variable will be appended to this

# FOR PRERELEASES: make always debug builds
#ifneq (,$(findstring 0,$(VERSION_V)))
#    DEBUG+=-g3 -DDEBUG
#endif

# If SSLFLAGS was set to empty, empty the win version too
ifndef SSLFLAGS
    SSLFLAGS_WIN=
endif


# Compile all that stuff
all: plugin tools clean

# DEBUG MODE
#   convinience invocation for debug build fpr GDB
#   -g3:     gdb debugging symbols
#   -O0:     no optimizations, so we get better dbg output (but slows don code significantly)
#   -DDEBUG: makes debug code active (prints internal state to stdout every sec)
debug: all-debug
all-debug:
	make DEBUG+="-g3 -Og -DDEBUG" all

# build just the linux plugin in debug mode
plugin-debug:
	make DEBUG+="-g3 -Og -DDEBUG" plugin

# make the plugin
plugin: outname=fgcom-mumble.so
plugin: libs
	$(CC) -shared -fPIC -o $(outname) $(lib_OBJS) fgcom-mumble.cpp $(SSLFLAGS) $(CFLAGS) $(THREADS_UNIX)

# make all the libs
libs:  $(lib_OBJS)

%.o : %.cpp
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(THREADS_UNIX)

# Compile testing tools
tools: libs
	$(CC) -o test/geotest lib/radio_model.o lib/audio.o test/geotest.cpp $(CFLAGS)
	$(CC) -o test/frqtest lib/radio_model.o lib/audio.o test/frqtest.cpp $(CFLAGS)


# catch2 unit tests linking against main
test: libs test/catch2/tests-main.o test/catch2/tests-main.o test/catch2/radioModelTest.o
	$(CC) -o test/catch2/radioModelTest.catch2 test/catch2/tests-main.o lib/radio_model.o lib/audio.o test/catch2/radioModelTest.o $(CFLAGS) && test/catch2/radioModelTest.catch2
# ^ add more

# clean compile results
clean:
	rm -f *.o *.rc lib/*.o test/catch2/*.catch2

# clean compile results and binarys
clean-all: clean
	rm -f test/geotest test/frqtest
	rm -f fgcom-mumble*.so
	rm -f *.exe test/*.exe *.dll lib/*.dll
	rm -f test/catch2/*.o



# Build all win64 stuff
#   apt-get install mingw-w64
all-win: plugin-win64 tools-win64 clean

# build win64 test tools
tools-win64: CC=x86_64-w64-mingw32-g++-posix
tools-win64:
	$(CC) -o test/geotest.exe lib/radio_model.cpp lib/audio.cpp test/geotest.cpp -static-libgcc -static-libstdc++ $(CFLAGS)
	$(CC) -o test/frqtest.exe lib/radio_model.cpp lib/audio.cpp test/frqtest.cpp -static-libgcc -static-libstdc++ $(CFLAGS)

# build win64 plugin-dll and openssl
plugin-win64: openssl-win plugin-win64-only

plugin-win32: openssl-win32 plugin-win32-only

# just the windows plugin, no ssl in case we want to build repetively but want to avoid building openssl each time
plugin-win64-only: outname=fgcom-mumble.dll
plugin-win64-only: mingwprefix=x86_64-w64-mingw32-
plugin-win64-only: CC=$(mingwprefix)g++-posix
plugin-win64-only: plugin-win-dllresource
	# Build plugin win64
	$(CC) -fPIC --shared -DMINGW_WIN64 -o $(outname) dllResource.o lib/io_plugin.cpp lib/radio_model.cpp lib/audio.cpp lib/io_UDPServer.cpp lib/io_UDPClient.cpp lib/garbage_collector.cpp fgcom-mumble.cpp $(SSLFLAGS_WIN) $(CFLAGS_WIN) $(THREADS_WIN)

plugin-win32-only: outname=fgcom-mumble-x86_32.dll
plugin-win32-only: mingwprefix=i686-w64-mingw32-
plugin-win32-only: CC=$(mingwprefix)g++-posix
plugin-win32-only: plugin-win-dllresource
	# Build plugin win32
	$(CC) -m32 -fPIC --shared -DMINGW_WIN32 -o $(outname) dllResource.o lib/io_plugin.cpp lib/radio_model.cpp lib/audio.cpp lib/io_UDPServer.cpp lib/io_UDPClient.cpp lib/garbage_collector.cpp fgcom-mumble.cpp $(SSLFLAGS_WIN) $(CFLAGS_WIN) $(THREADS_WIN)

GITVER:=$(shell git log -1 --pretty=format:"%h")
GITDATE:=$(shell git log -1 --pretty=format:"%cd" --date=short)
PLUGIN_VERSION_V:=$(shell grep -m1 FGCOM_VERSION_MAJOR fgcom-mumble.h |grep -E -o '[0-9]+')
PLUGIN_VERSION_M:=$(shell grep -m1 FGCOM_VERSION_MINOR fgcom-mumble.h |grep -E -o '[0-9]+')
PLUGIN_VERSION_P:=$(shell grep -m1 FGCOM_VERSION_PATCH fgcom-mumble.h |grep -E -o '[0-9]+')
plugin-win-dllresource:
	# Build DLL resource file
	@echo "1 VERSIONINFO" > dllResource.rc
	@echo "FILEVERSION     $(PLUGIN_VERSION_V),$(PLUGIN_VERSION_M),$(PLUGIN_VERSION_P),0" >> dllResource.rc
	@echo "PRODUCTVERSION  $(PLUGIN_VERSION_V),$(PLUGIN_VERSION_M),$(PLUGIN_VERSION_P),0" >> dllResource.rc
	@echo "BEGIN" >> dllResource.rc
	@echo "  BLOCK \"StringFileInfo\"" >> dllResource.rc
	@echo "  BEGIN" >> dllResource.rc
	@echo "    BLOCK \"040904E4\"" >> dllResource.rc
	@echo "    BEGIN" >> dllResource.rc
	@echo "      VALUE \"CompanyName\", \"B. Hallinger (https://github.com/hbeni/fgcom-mumble)\"" >> dllResource.rc
	@echo "      VALUE \"Comments\", \"Project page: https://github.com/hbeni/fgcom-mumble\"" >> dllResource.rc
	@echo "      VALUE \"FileDescription\", \"FGCom-mumble plugin for Mumble\"" >> dllResource.rc
	@echo "      VALUE \"FileVersion\", \"$(PLUGIN_VERSION_V).$(PLUGIN_VERSION_M).$(PLUGIN_VERSION_P)\"" >> dllResource.rc
	@echo "      VALUE \"InternalName\", \"fgcom-mumble\"" >> dllResource.rc
	@echo "      VALUE \"LegalCopyright\", \"(c) B. Hallinger, GPLv3 license\"" >> dllResource.rc
	@echo "      VALUE \"OriginalFilename\", \"$(outname)\"" >> dllResource.rc
	@echo "      VALUE \"ProductName\", \"FGCom-mumble\"" >> dllResource.rc
	@echo "      VALUE \"ProductVersion\", \"$(PLUGIN_VERSION_V).$(PLUGIN_VERSION_M).$(PLUGIN_VERSION_P)\"" >> dllResource.rc
	@echo "      VALUE \"LastChange\", \"$(GITDATE) ($(GITVER))\"" >> dllResource.rc
	@echo "    END" >> dllResource.rc
	@echo "  END" >> dllResource.rc
	@echo "  BLOCK \"VarFileInfo\"" >> dllResource.rc
	@echo "  BEGIN" >> dllResource.rc
	@echo "    VALUE \"Translation\", 0x409, 1252" >> dllResource.rc
	@echo "  END" >> dllResource.rc
	@echo "END" >> dllResource.rc
	$(mingwprefix)windres dllResource.rc dllResource.o

# shortcut for building natively on macOS
plugin-macOS: CC=g++-11
plugin-macOS: outname=fgcom-mumble-macOS.bundle
plugin-macOS:
	make CC=$(CC) outname=$(outname) CFLAGS="-I/usr/local/opt/openssl/include/ -L/usr/local/opt/openssl/lib/" plugin

# OpenSSL (static build)
# The sources are located under lib/openssl as git submodule, and supposed to point to the latest stable head
# Info on configure options: https://wiki.openssl.org/index.php/Compilation_and_Installation
openssl-win:
ifdef SSLFLAGS
	@echo "BUILD OpenSSL"
	git submodule init
	git submodule update
	cd lib/openssl/ && git reset --hard
	cd lib/openssl/ && ./Configure mingw64 -static no-pinshared no-weak-ssl-ciphers no-ssl2 no-ssl3 no-idea no-dtls1 --cross-compile-prefix=x86_64-w64-mingw32- && make clean && make -j4
else
	@echo "Skipping building OpenSSL"
endif

openssl-win32:
ifdef SSLFLAGS
	@echo "BUILD OpenSSL"
	git submodule init
	git submodule update
	cd lib/openssl/ && git reset --hard
	cd lib/openssl/ && ./Configure mingw -static no-pinshared no-weak-ssl-ciphers no-ssl2 no-ssl3 no-idea no-dtls1 --cross-compile-prefix=i686-w64-mingw32- && make clean && make -j4
else
	@echo "Skipping building OpenSSL"
endif


