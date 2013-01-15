#Makefile for mstunnel
#
all: 
	make -C lib/rb
	make -C src 

clean:
	make -C lib/rb clean
	make -C src clean

distclean: 
	make -C lib/rb clean
	make -C src distclean
