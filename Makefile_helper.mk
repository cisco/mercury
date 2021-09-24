# definitions for colorized output
COLOR_RED    = "\033[0;31m"
COLOR_GREEN  = "\033[0;32m"
COLOR_YELLOW = "\033[0;33m"
COLOR_OFF    = "\033[0m"

CXX     = g++
CC      = gcc
CFLAGS  = --std=c++17
CFLAGS += -O3
# CFLAGS += -march=x86-64 -mtune=generic
CFLAGS += -Wall -Wpedantic -Wextra -Wno-deprecated $(CDEFS) $(MSV)
CFLAGS += -Wno-missing-braces # this flag squelches a gcc bug that causes a spurious warning
CFLAGS += -Wno-narrowing      # needed for oid.h to suppress spurious (un)signed char error
CFLAGS += $(OPTFLAGS)

# extra flags
CFLAGS += -fno-rtti
CFLAGS += -Wformat
CLFAGS += -Wformat-security
CFLAGS += -Wno-deprecated-declarations
CFLAGS += -Wno-long-long
CFLAGS += -Wmissing-noreturn
CFLAGS += -Wunreachable-code
CFLAGS += -fvisibility=hidden
CFLAGS += -DNDEBUG
# CFLAGS += -g
# CFLAGS += -ggdb
CFLAGS += -fno-builtin-malloc
CFLAGS += -fno-builtin-calloc
CFLAGS += -fno-builtin-realloc
CFLAGS += -fno-builtin-free
ifeq ($(CXX),g++)
CFLAGS += -fno-gnu-unique
endif