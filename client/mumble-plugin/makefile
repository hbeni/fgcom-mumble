.PHONY : all all-debug plugin libs test clean clean-all debug-on
CC=g++
DEBUG=
CFLAGS=-I. -I./lib $(DEBUG)

# Compile all that stuff
all: plugin test clean

# convinience invocation for debug build fpr GDB
all-debug:
	make DEBUG=-g3 all

# make the plugin
plugin: libs
	$(CC) -shared -fPIC -o fgcom-mumble.so lib/radio_model.o fgcom-mumble.cpp $(CFLAGS)

# make all the libs
libs:  lib/radio_model.o #libs/more.o

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
