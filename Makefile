# $Id$
OBJECTS=bw.o
TARGET=bw
LIBS=-lpcap
CC=gcc
LD=gcc
CFLAGS=-g -Wall
LDFLAGS=

all: $(TARGET)
clean:
	rm -rf *.o $(TARGET) *~ .depend

$(TARGET): $(OBJECTS) 
	$(LD) $(LDFLAGS) $(OBJECTS) -o $(TARGET) $(LIBS)

depend:
	$(CC) $(CFLAGS) -MM $(OBJECTS:%.o=%.c)> .depend

.c.o:
	$(CC) $(CFLAGS) -c $<

