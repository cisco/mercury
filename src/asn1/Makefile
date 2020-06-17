# makefile for mercury asn1 tools
#

SHELL = /bin/sh

srcdir = .

INSTALL = /usr/bin/install -c
INSTALLDATA = /usr/bin/install -c -m 644

prefix = /usr/local
exec_prefix=${prefix}
bindir = ${exec_prefix}/bin
localstatedir = ${prefix}/var/mercury
datarootdir = ${prefix}/share/mercury

CFLAGS = --std=c++11 -Wall -Wpedantic -Wextra -O2 $(OPTFLAGS) # -DASN1_DEBUG=1

.PHONY: all
all: cert-analyze oidc oid.h

cert-analyze: cert-analyze.cc x509.h asn1.h oid.h ../utils.h ../json_object.hh
	$(CXX) $(CFLAGS) -o cert-analyze cert-analyze.cc ../parser.c ../utils.c # -lmhash

oidc: oidc.cc
	$(CXX) $(CFLAGS) -o oidc oidc.cc

oid.h: oidc $(wildcard *.asn1)
	./oidc $(sort $(wildcard *.asn1)) > oid.h

.PHONY: clean 
clean:
	rm -rf cert-analyze oidc gmon.out
	for file in cert-analyze.cc oidc.cc Makefile README.md configure.ac $(wildcard *.asn1); do if [ -e "$$file~" ]; then rm -f "$$file~" ; fi; done

.PHONY: distclean
distclean: clean
	rm -rf oid-list

# fuzz testing with american fuzzy lop
#
FUZZ_CMD =
.PHONY: fuzz-test
fuzz-test:
	@echo "running fuzz test with afl-g++"
	rm -f cert-analyze && $(MAKE) CXX=afl-g++ CC=afl-gcc
	mv cert-analyze ./afl-cert-analyze
	afl-fuzz -i afl_data -o afl_findings ./afl-cert-analyze --input @@ $(FUZZ_CMD)

# EOF
