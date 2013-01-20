ROOTDIR=..
LIBS=-L$(ROOTDIR)/lib/cli/ -lcli -lrt
INC=$(ROOTDIR)/inc

BUILDDIR=${ROOTDIR}/cli/build
SOURCES=$(wildcard *.c)
OBJ_FILES= $(patsubst %.c,${BUILDDIR}/%.o,${SOURCES})

TARGET=${ROOTDIR}/cli/bin/mstcli

MAJOR = 1
MINOR = 9
REVISION = 7

CC = gcc
DEBUG = -g
OPTIM = -O3
CFLAGS += $(DEBUG) $(OPTIM) -Wall -std=c99 -pedantic -Wformat-security -Wno-format-zero-length -Wwrite-strings -Wformat -fdiagnostics-show-option -Wextra -Wsign-compare -Wcast-align -Wno-unused-parameter

CFLAGS+=-I${INC}
CFLAGS+=-I${ROOTDIR}/lib/cli

all: ${TARGET}
	gcc -g -o ${TARGET} ${BUILDDIR}/*.o ${LIBS}

build:
	@mkdir -p ${ROOTDIR}/cli/build
	@mkdir -p ${ROOTDIR}/cli/bin

${BUILDDIR}/%.o:%.c ${INC}/*.h
	$(CC) $(CPPFLAGS) ${CFLAGS} -c $< -o $@

${TARGET}: build ${OBJ_FILES}

clean:
	@rm -f *.o ${OBJ_FILES}


distclean: clean
	@rm -f ${TARGET}

