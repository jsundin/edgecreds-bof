all: edgecreds.x64.o edgecreds.x86.o

CFLAGS := -c -DPRINT_PROCESS_OWNER

edgecreds.x64.o: *.c *.h
	x86_64-w64-mingw32-gcc main.c -o edgecreds.x64.o $(CFLAGS)

edgecreds.x86.o: *.c *.h
	i686-w64-mingw32-gcc main.c -o edgecreds.x86.o $(CFLAGS)

clean:
	rm -f edgecreds.x64.o edgecreds.x86.o

install: edgecreds.x64.o edgecreds.x86.o extension.json
	mkdir -p ~/.sliver-client/extensions/edgecreds
	cp edgecreds.x64.o edgecreds.x86.o extension.json ~/.sliver-client/extensions/edgecreds/
