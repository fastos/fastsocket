# Makefile for server

CC = gcc
CFLAGS = -Wall -g 
LDFLAGS = -pthread

all: server

server: server.c server.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -rf server
