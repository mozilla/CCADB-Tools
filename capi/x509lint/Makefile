CC = gcc
LD = $(CC)
RM = rm

CFLAGS = -g -Wall -O2 -std=c99
LIBS = -lcrypto

UNAME_O := $(shell uname -o)
ifeq ($(UNAME_O),Cygwin)
    LIBS += -liconv
endif

OBJECTS = x509lint.o checks.o messages.o asn1_time.o

x509lint: $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

clean:
	$(RM) -f x509lint *.o

checks.o: checks.c checks.h
x509lint.o: x509lint.c checks.h messages.h
messages.o: messages.c checks.h
