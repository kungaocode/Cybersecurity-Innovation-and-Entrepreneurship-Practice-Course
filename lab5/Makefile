# Makefile for Experiment 5 & 6 - HE Convolution with OpenFHE
# ================================================================

OPENFHE_DIR = /home/kun/Desktop/experiment3/openfhe-install

CXX = g++
CXXFLAGS = -std=c++17 -O2 -march=native -fopenmp \
           -I$(OPENFHE_DIR)/include \
           -I$(OPENFHE_DIR)/include/openfhe \
           -I$(OPENFHE_DIR)/include/openfhe/core \
           -I$(OPENFHE_DIR)/include/openfhe/pke \
           -I$(OPENFHE_DIR)/include/openfhe/binfhe

LDFLAGS = -L$(OPENFHE_DIR)/lib \
          -Wl,-rpath,$(OPENFHE_DIR)/lib \
          -lOPENFHEpke -lOPENFHEcore -lOPENFHEbinfhe \
          -fopenmp -pthread

TARGETS = experiment5 experiment6

.PHONY: all clean

all: $(TARGETS)

experiment5: experiment5_baseline.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

experiment6: experiment6_optimized.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f experiment5 experiment6
