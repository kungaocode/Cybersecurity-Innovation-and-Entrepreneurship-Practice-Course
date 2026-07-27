.PHONY: env clone-secp build-secp bench run report clean

SECP256K1_DIR = secp256k1

# Create conda environment
env:
	conda env create -f environment.yml
	@echo "Environment 'ecdsa_lab' created. Activate with: conda activate ecdsa_lab"

# Clone secp256k1
clone-secp:
	@if [ -d "$(SECP256K1_DIR)" ]; then \
		echo "secp256k1 already cloned."; \
	else \
		git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git $(SECP256K1_DIR); \
		echo "Cloned secp256k1."; \
	fi

# Build secp256k1 with all modules
build-secp: clone-secp
	cd $(SECP256K1_DIR) && \
	./autogen.sh && \
	./configure \
		--enable-module-ecdh \
		--enable-module-schnorrsig \
		--enable-module-ellswift \
		--enable-experimental \
		--enable-module-musig \
		--with-ecmult-window=15 \
		--with-ecmult-gen-kb=86 && \
	make -j$$(nproc)
	@echo "secp256k1 built. Running make check..."
	cd $(SECP256K1_DIR) && make check -j$$(nproc)
	@echo "secp256k1 build verified."

# Run benchmarks
bench: build-secp
	@echo "Running benchmarks..."
	cd $(SECP256K1_DIR) && ./bench_ecmult > ../analysis/bench_results.txt 2>&1 || true
	cd $(SECP256K1_DIR) && ./bench_internal >> ../analysis/bench_results.txt 2>&1 || true
	cat analysis/bench_results.txt

# Run Python ECDSA forgery demo
run:
	conda run -n ecdsa_lab python ecdsa_primitives.py
	conda run -n ecdsa_lab python ecdsa_forgery.py

# Compile LaTeX report
report:
	cd report && xelatex -interaction=nonstopmode main.tex && xelatex main.tex

# Clean
clean:
	rm -rf analysis/bench_results.txt
	rm -f report/main.aux report/main.log report/main.out report/main.pdf report/main.toc
