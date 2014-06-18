# Makefile for create_fw
#
CC=gcc
CFLAGS=-c -Wall -O2 -g
LDFLAGS=
SOURCES=create_fw.c
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=create_fw
BLOB=isci_firmware.bin

all: $(SOURCES) $(EXECUTABLE) $(BLOB)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -O $@

$(BLOB): $(EXECUTABLE)
	./$(EXECUTABLE) >$@

clean:
	rm -f *.o $(EXECUTABLE)
