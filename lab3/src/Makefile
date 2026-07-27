#
# Makefile for SM3 Hash Algorithm Implementation
#
# Experiment 2: SM3 Optimization
# - Phase 1: Pure C baseline (make baseline)
# - Phase 2a: AVX2 SIMD x86_64 (make avx2)
# - Phase 2b: ARM NEON SIMD aarch64 (make neon)
#
# Adapted from openHiTLS (Mulan PSL v2).
#

ARCH := $(shell uname -m)
CC   := gcc

# ---- Compiler flags ----

CFLAGS_BASE  := -O3 -Wall -Wextra -std=c99
CFLAGS_AVX2  := -O3 -Wall -Wextra -std=c99 -mavx2 -msse4.1 -mssse3 -DSM3_HAS_SIMD
CFLAGS_NEON  := -O3 -Wall -Wextra -std=c99 -march=armv8-a+simd -DSM3_HAS_SIMD

# Link with librt if needed (older glibc for clock_gettime)
LDFLAGS      := -lrt

# ---- Auto-detect default target ----
ifeq ($(ARCH), x86_64)
    TARGET := sm3_avx2
else ifeq ($(ARCH), aarch64)
    TARGET := sm3_neon
else
    TARGET := sm3_baseline
endif

# ---- Source files ----
SRC_COMMON := sm3_public.c sm3_baseline.c
SRC_AVX2   := sm3_avx2.c
SRC_NEON   := sm3_neon.c
SRC_TEST   := test_sm3.c

# ---- Targets ----

.PHONY: all baseline avx2 neon sm3_baseline sm3_avx2 sm3_neon
.PHONY: test test-baseline test-avx2 test-neon clean help

all: $(TARGET)

# Build baseline version (pure C, no SIMD)
baseline:
	$(CC) $(CFLAGS_BASE) -o test_baseline $(SRC_COMMON) $(SRC_TEST) $(LDFLAGS)
	@echo "Built: test_baseline (pure C, no SIMD)"

# Build AVX2 version (x86_64)
avx2:
ifeq ($(ARCH), x86_64)
	$(CC) $(CFLAGS_AVX2) -o test_avx2 $(SRC_COMMON) $(SRC_AVX2) $(SRC_TEST) $(LDFLAGS)
	@echo "Built: test_avx2 (AVX2 SIMD message expansion)"
else
	$(error AVX2 target requires x86_64 architecture (current: $(ARCH)))
endif

# Build NEON version (aarch64)
neon:
ifeq ($(ARCH), aarch64)
	$(CC) $(CFLAGS_NEON) -o test_neon $(SRC_COMMON) $(SRC_NEON) $(SRC_TEST) $(LDFLAGS)
	@echo "Built: test_neon (NEON SIMD message expansion)"
else
	$(error NEON target requires aarch64 architecture (current: $(ARCH)))
endif

sm3_baseline: baseline
sm3_avx2: avx2
sm3_neon: neon

# Run tests
test: all
	@echo ""
ifeq ($(ARCH), x86_64)
	./test_avx2
else ifeq ($(ARCH), aarch64)
	./test_neon
else
	./test_baseline
endif

test-baseline: baseline
	@echo ""
	./test_baseline

test-avx2: avx2
	@echo ""
	./test_avx2

test-neon: neon
	@echo ""
	./test_neon

# Clean
clean:
	rm -f test_baseline test_avx2 test_neon
	rm -f *.o
	@echo "Cleaned."

# Help
help:
	@echo "SM3 Hash Algorithm - Build Targets"
	@echo "=================================="
	@echo "Detected architecture: $(ARCH)"
	@echo "Default target: $(TARGET)"
	@echo ""
	@echo "  make              - Build default for current arch"
	@echo "  make baseline     - Build pure C baseline"
	@echo "  make avx2         - Build AVX2 SIMD (x86_64)"
	@echo "  make neon         - Build NEON SIMD (aarch64)"
	@echo "  make test         - Build + run test suite"
	@echo "  make test-baseline- Build + run baseline test"
	@echo "  make test-avx2    - Build + run AVX2 test"
	@echo "  make test-neon    - Build + run NEON test"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make help         - Show this help"
