#Makefile for mstunnel
#
all: 
	make -C lib/rb
	make -C src 
	make -C cli 

clean:
	make -C lib/rb clean
	make -C src clean
	make -C cli clean 

distclean: 
	make -C lib/rb clean
	make -C src distclean
	make -C cli distclean
