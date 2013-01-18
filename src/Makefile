#Makefile for mstunnel
#
ROOTDIR=..
LIBS=-levent -ldl -lpthread -L$(ROOTDIR)/lib/rb -lmstrb
INC=$(ROOTDIR)/inc
#INC+=-I/usr/include/glib-2.0/

BUILDDIR=${ROOTDIR}/build
SOURCES=$(wildcard *.c)
OBJ_FILES= $(patsubst %.c,${BUILDDIR}/%.o,${SOURCES}) 

MST_FLAGS=-D_EVENT_HAVE_PTHREADS
MST_FLAGS+=-D__DEV_TEST__
MST_FLAGS+=-D__USE_MM__

TARGET=${ROOTDIR}/bin/mstunnel
CFLAGS=-g -O2 -Wall ${MST_FLAGS}
CFLAGS+=-I${ROOTDIR}/lib
CFLAGS+=-I${ROOTDIR}/lib/rb
CFLAGS+=-I${ROOTDIR}/lib/ds
CFLAGS+=-I${INC}

all: ${TARGET}
	gcc -g -o ${TARGET} ${BUILDDIR}/*.o ${LIBS}

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
