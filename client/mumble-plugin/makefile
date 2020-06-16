CC=g++
DEBUGFLAG=-g3
CFLAGS=-I. -I./lib $(DEBUGFLAG)

plugin: radio_model.o fgcom-mumble.o
	$(CC) -shared -o fgcom-mumble.so lib/radio_model.o fgcom-mumble.o $(CFLAGS)
	
fgcom-mumble.o:
	$(CC) -fPIC -c -o fgcom-mumble.o fgcom-mumble.cpp $(CFLAGS)

radio_model.o:
	$(CC) -fPIC -c -o lib/radio_model.o lib/radio_model.cpp $(CFLAGS)
	
clean:
	rm *.so *.o lib/*.o
