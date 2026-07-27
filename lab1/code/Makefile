.PHONY: env run report clean

# Create conda environment
env:
	conda env create -f environment.yml
	@echo "Environment 'bitcoin' created. Activate with: conda activate bitcoin"

# Run the full pipeline
run:
	conda run -n bitcoin python main.py

# Run with an existing TxID (skip wallet creation)
run-txid:
	conda run -n bitcoin python main.py --txid $(TXID)

# Compile LaTeX report
report:
	cd report && \
	pdflatex main.tex && \
	pdflatex main.tex

# Clean outputs
clean:
	rm -rf output/*
	rm -f report/main.aux report/main.log report/main.out report/main.pdf report/main.toc
