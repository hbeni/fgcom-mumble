.PHONY : all all-debug plugin test clean clean-all debug-on
CC=g++
DEBUG=
CFLAGS=-I. -I./lib $(DEBUG)

# Compile all that stuff
all: plugin test clean

# convinience invocation for debug build fpr GDB
all-debug:
	make DEBUG=-g3 all

# make the plugin
plugin: radio_model.o
	$(CC) -shared -fPIC -o fgcom-mumble.so lib/radio_model.o fgcom-mumble.cpp $(CFLAGS)

# make the rdio model lib
radio_model.o:
	$(CC) -fPIC -c -o lib/radio_model.o lib/radio_model.cpp $(CFLAGS)



# Compile tests and stuff
test: radio_model.o
	$(CC) -o test/geotest lib/radio_model.o test/geotest.cpp $(CFLAGS)

# clean compile results
clean:
	rm -f *.so *.o lib/*.o

# clean compile results and binarys
clean-all: clean
	rm -f test/geotest
	rm -f fgcom-mumble.so
