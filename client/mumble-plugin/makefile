.PHONY : all all-debug plugin libs test clean clean-all debug-on
CC=g++
DEBUG=
CFLAGS=-I. -I./lib -pthread $(DEBUG)

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
	$(CC) -shared -fPIC -o fgcom-mumble.so lib/plugin_io.o lib/radio_model.o fgcom-mumble.cpp $(CFLAGS)

# make all the libs
libs:  lib/radio_model.o lib/plugin_io.o

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
	x86_64-w64-mingw32-g++ -static -o fgcom-mumble.dll lib/plugin_io.cpp lib/radio_model.cpp fgcom-mumble.cpp --shared -static-libgcc -static-libstdc++ -DMINGW_WIN64 -lws2_32 $(CFLAGS)



# Build a release tarball
release: clean-all plugin plugin-win64
	rm -f fgcom-mumble-linux*.tar.gz
	rm -f fgcom-mumble-windows*.zip
	mkdir fgcom-mumble-linux
	mkdir fgcom-mumble-linux/plugin
	cp ../../README.md ../../LICENSE ../../plugin.spec.md fgcom-mumble-linux
	cp fgcom-mumble.so fgcom-mumble-linux/plugin
	cp -r ../fgfs/ fgcom-mumble-linux
	tar -czf fgcom-mumble-linux.tar.gz fgcom-mumble-linux/
	rm -rf fgcom-mumble-linux
	mkdir fgcom-mumble-windows
	mkdir fgcom-mumble-windows/plugin
	cp ../../README.md ../../LICENSE ../../plugin.spec.md fgcom-mumble-windows
	cp fgcom-mumble.dll fgcom-mumble-windows/plugin
	cp -r ../fgfs/ fgcom-mumble-windows
	zip -r fgcom-mumble-windows.zip fgcom-mumble-windows
	rm -rf fgcom-mumble-windows
