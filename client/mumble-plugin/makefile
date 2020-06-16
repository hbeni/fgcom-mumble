CC=g++
DEBUGFLAG=-g3
CFLAGS=-I. -I./lib $(DEBUGFLAG)

plugin: radio_model.o fgcom-mumble.o
	$(CC) -shared -o fgcom-mumble.so lib/radio_model.o fgcom-mumble.o $(CFLAGS)
	
fgcom-mumble.o:
	$(CC) -fPIC -c -o fgcom-mumble.o fgcom-mumble.cpp $(CFLAGS)

radio_model.o:
	$(CC) -fPIC -c -o lib/radio_model.o lib/radio_model.cpp $(CFLAGS)


test: radio_model.o
	$(CC) -o test/geotest lib/radio_model.o test/geotest.cpp $(CFLAGS)

clean:
	rm -f *.so *.o lib/*.o

clean-all: clean
	rm -f test/geotest
	rm -f fgcom-mumble.so
