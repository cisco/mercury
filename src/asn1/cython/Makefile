# Makefile for cert_analyze python module
#

cert_analyze.so: cert_analyze.pyx
	CC=g++ python setup.py build_ext --inplace
	strip cert_analyze.so

clean:
	rm cert_analyze.so cert_analyze.cpp


