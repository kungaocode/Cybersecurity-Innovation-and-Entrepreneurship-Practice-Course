#
# AES Experiment Makefile
#
# Builds four AES implementations (S-box, T-table, Shuffle, AES-NI)
# plus working modes (CTR, GCM, XTS) and a benchmark harness.
#

CC       = gcc
CFLAGS   = -Wall -Wextra -O3 -std=c11
LDFLAGS  =

# SIMD / AES-NI flags (x86 only)
ARCH_FLAGS = -march=native
# If -march=native is not desired, uncomment and adjust:
# ARCH_FLAGS = -msse2 -mssse3 -maes -mpclmul

# Detect if we are on x86
UNAME_M := $(shell uname -m)
ifneq ($(filter x86_64 amd64 i386 i686,$(UNAME_M)),)
  CFLAGS += $(ARCH_FLAGS)
endif

# Source files
SRCS = aes_tables.c aes_sbox.c aes_tbox.c aes_shuffle.c aes_ni.c aes_modes.c

# Object files
OBJS = $(SRCS:.c=.o)

# Target
TARGET = aes_benchmark

.PHONY: all clean run test

all: $(TARGET)

$(TARGET): $(OBJS) benchmark.c
	$(CC) $(CFLAGS) -o $@ $(OBJS) benchmark.c $(LDFLAGS)

%.o: %.c aes.h aes_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

# aes_shuffle needs SSSE3 intrinsics header
aes_shuffle.o: CFLAGS += -msse2 -mssse3

# aes_ni needs AES-NI intrinsics
aes_ni.o: CFLAGS += -msse2 -maes -mpclmul

# benchmark uses clock_gettime
benchmark.o: CFLAGS += -D_POSIX_C_SOURCE=199309L

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

distclean: clean
	rm -f *.o *.out

help:
	@echo "Targets:"
	@echo "  all      - Build the benchmark program"
	@echo "  run      - Build and run"
	@echo "  test     - Build and run tests"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help"
