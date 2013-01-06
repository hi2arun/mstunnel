UNAME = $(shell sh -c 'uname -s 2>/dev/null || echo not')
DESTDIR =
PREFIX = /usr/local

MAJOR = 0
MINOR = 1
REVISION = 1
LIB = libmstrb.so

CC = gcc
AR = ar
ARFLAGS = rcs
DEBUG = -g
OPTIM = -O3
CFLAGS += $(DEBUG) $(OPTIM) -Wall -std=c99 -pedantic -Wformat-security -Wno-format-zero-length -Werror -Wwrite-strings -Wformat -fdiagnostics-show-option -Wextra -Wsign-compare -Wcast-align -Wno-unused-parameter
LDFLAGS += -shared
LIBPATH += -L.

ifeq ($(UNAME),Darwin)
LDFLAGS += -Wl,-install_name,$(LIB).$(MAJOR).$(MINOR)
else
LDFLAGS += -Wl,-soname,$(LIB).$(MAJOR).$(MINOR)
LIBS = -lcrypt
endif

all: $(LIB) rbtest

$(LIB): mstrb.o
	$(CC) -o $(LIB).$(MAJOR).$(MINOR).$(REVISION) $^ $(LDFLAGS) $(LIBS)
	-rm -f $(LIB) $(LIB).$(MAJOR).$(MINOR)
	ln -s $(LIB).$(MAJOR).$(MINOR).$(REVISION) $(LIB).$(MAJOR).$(MINOR)
	ln -s $(LIB).$(MAJOR).$(MINOR) $(LIB)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -o $@ -c $<

mstrb.o: mstrb.h

rbtest: rbtest.o $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -L. -lmstrb

clean:
	rm -f *.o $(LIB)* rbtest
