#Makefile for mstunnel
#
ROOTDIR=..
LIBS=-levent -ldl
INC=${ROOTDIR}/inc

BUILDDIR=${ROOTDIR}/build
SOURCES=$(wildcard *.c)
OBJ_FILES= $(patsubst %.c,${BUILDDIR}/%.o,${SOURCES}) 

MST_FLAGS=-D_EVENT_HAVE_PTHREADS

TARGET=${ROOTDIR}/bin/mstunnel
CFLAGS=-g -O2 -Wall -I${INC} ${MST_FLAGS}

all: ${TARGET}
	gcc -o ${TARGET} ${BUILDDIR}/*.o ${LIBS}

build:
	@mkdir -p ${ROOTDIR}/build
	@mkdir -p ${ROOTDIR}/bin

${TARGET}: build ${OBJ_FILES}

${BUILDDIR}/%.o:%.c ${INC}/*.h
	gcc ${CFLAGS} -c $< -o $@ 

clean:
	@rm -f ${OBJ_FILES}

distclean: clean
	@rm -f ${TARGET}
