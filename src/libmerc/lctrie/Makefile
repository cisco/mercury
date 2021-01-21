
all: lctrie_test

lctrie_test: lctrie_test.o lctrie.o lctrie_bgp.o lctrie_ip.o common.o

liblctrie.a: lctrie.o lctrie_bgp.o lctrie_ip.o common.o
	ar rcs liblctrie.a $^

clean:
	rm -rf .d
	rm -f *.o
	rm -f lctrie_test
	rm -f liblctrie.a

CC     = g++
CFLAGS = -g -ggdb -std=c++11 -Wall -O3 -Wno-sign-compare -fPIC
LDFLAGS = -g -ggdb -O3
LDLIBS = 

# autodep stuff

DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
COMPILE.cc = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
POSTCOMPILE = mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d

%.o : %.c
%.o : %.c $(DEPDIR)/%.d
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o : %.cc
%.o : %.cc $(DEPDIR)/%.d
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o : %.cxx
%.o : %.cxx $(DEPDIR)/%.d
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

$(DEPDIR)/%.d: ;
.PRECIOUS: $(DEPDIR)/%.d

-include $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRCS)))


