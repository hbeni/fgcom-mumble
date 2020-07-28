.PHONY : all all-debug plugin libs test clean clean-all debug-on
CC=g++
DEBUG=
CFLAGS=-I. -I./lib -pthread $(DEBUG)

# get version
GITCOMMIT:=$(shell git log -1 --pretty=format:"%h")
GITDATE:=$(shell git log -1 --pretty=format:"%cd" --date=short)
VERSION_V:=$(shell grep -m1 FGCOM_VERSION_MAJOR fgcom-mumble.cpp |grep -E -o '[0-9]')
VERSION_M:=$(shell grep -m1 FGCOM_VERSION_MINOR fgcom-mumble.cpp |grep -E -o '[0-9]')
VERSION_P:=$(shell grep -m1 FGCOM_VERSION_PATCH fgcom-mumble.cpp |grep -E -o '[0-9]')
VERSION:=$(VERSION_V).$(VERSION_M).$(VERSION_P)



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
	$(CC) -shared -fPIC -o fgcom-mumble.so lib/plugin_io.o lib/radio_model.o lib/audio.o lib/rdfUDP.o lib/garbage_collector.o fgcom-mumble.cpp $(CFLAGS)

# make all the libs
libs:  lib/radio_model.o lib/plugin_io.o lib/audio.o lib/rdfUDP.o lib/garbage_collector.o

%.o : %.cpp
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

# Compile tests and stuff
test: libs
	$(CC) -o test/geotest lib/radio_model.o test/geotest.cpp $(CFLAGS)

# clean compile results
clean:
	rm -f *.o lib/*.o

# clean compile results and binarys
clean-all: clean
	rm -f test/geotest
	rm -f fgcom-mumble.so
	rm -f *.exe test/*.exe *.dll lib/*.dll



# Build all win64 stuff
#   apt-get install mingw-w64
all-win: plugin-win64 test-win64 clean

# build win64 test tools
test-win64:
	x86_64-w64-mingw32-g++ -o test/geotest.exe lib/radio_model.cpp test/geotest.cpp -static-libgcc -static-libstdc++ $(CFLAGS)

# build win64 plugin-dll
plugin-win64: libs
	x86_64-w64-mingw32-g++ -static -o fgcom-mumble.dll lib/plugin_io.cpp lib/radio_model.cpp lib/audio.cpp lib/rdfUDP.cpp lib/garbage_collector.cpp fgcom-mumble.cpp --shared -static-libgcc -static-libstdc++ -DMINGW_WIN64 -Wl,-Bstatic -lpthread -lws2_32 $(CFLAGS)




# Build a release tarball
release: clean-all plugin plugin-win64
	@echo GIT commit $(GITCOMMIT) from $(GITDATE), V$(VERSION)
	head -n 1 ../../README.md > releaseReadme.md
	@echo Version: $(VERSION) \($(GITCOMMIT) $(GITDATE)\) >> releaseReadme.md
	tail +2 ../../README.md >> releaseReadme.md
	
	mkdir fgcom-mumble-linux-$(VERSION)
	mkdir fgcom-mumble-linux-$(VERSION)/plugin
	rm -f fgcom-mumble-linux*.tar.gz
	cp releaseReadme.md fgcom-mumble-linux-$(VERSION)/README.md
	cp ../../LICENSE ../../Readme.architecture.md ../plugin.spec.md fgcom-mumble-linux-$(VERSION)
	cp fgcom-mumble.so fgcom-mumble-linux-$(VERSION)/plugin
	cp -r ../fgfs/ fgcom-mumble-linux-$(VERSION)
	tar -czf fgcom-mumble-linux-$(VERSION).tar.gz fgcom-mumble-linux-$(VERSION)/
	rm -rf fgcom-mumble-linux-$(VERSION)
	
	mkdir fgcom-mumble-windows-$(VERSION)
	mkdir fgcom-mumble-windows-$(VERSION)/plugin
	rm -f fgcom-mumble-windows*.zip
	cp releaseReadme.md fgcom-mumble-windows-$(VERSION)/README.md
	cp ../../LICENSE ../../Readme.architecture.md ../plugin.spec.md fgcom-mumble-windows-$(VERSION)
	cp fgcom-mumble.dll fgcom-mumble-windows-$(VERSION)/plugin
	cp -r ../fgfs/ fgcom-mumble-windows-$(VERSION)
	zip -r fgcom-mumble-windows-$(VERSION).zip fgcom-mumble-windows-$(VERSION)
	rm -rf fgcom-mumble-windows-$(VERSION)
	
	rm releaseReadme.md

showVer:
	@echo "GITCOMMIT:$(GITCOMMIT)"
	@echo "GITDATE:$(GITDATE)"
	@echo "VERSION:$(VERSION)"
