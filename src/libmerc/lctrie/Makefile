
all: lctrie_test

lctrie_test: lctrie_test.o lctrie.o lctrie_bgp.o lctrie_ip.o

liblctrie.a: lctrie.o lctrie_bgp.o lctrie_ip.o
	ar rcs liblctrie.a $^

clean:
	rm -rf .d
	rm -f *.o
	rm -f lctrie_test
	rm -f liblctrie.a

CFLAGS = -g -ggdb -std=c++17 -Wall -O3 -fPIC -I/opt/homebrew/include# -Wno-sign-compare
LDFLAGS = -g -ggdb -O3 -L/opt/homebrew/lib
LDLIBS =

ifeq ($(COVERAGE_ENABLED),1)
ifeq ($(filter -O3, $(CFLAGS)), -O3)
    CFLAGS := $(filter-out -O3,$(CFLAGS))
	CFLAGS += -O0
endif
CFLAGS += -fprofile-arcs --coverage -ggdb -fprofile-update=atomic
LDFLAGS += --coverage
endif

# autodep stuff

DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

COMPILE.c = $(CXX) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
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


