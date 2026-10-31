# Build/run script for blocksig. Python needs no compilation, so the targets install dependencies, run the tests, the demo and the web page.

PYTHON ?= python3

.PHONY: all install test demo web clean

all: test demo

install:   ## python3 -m pip install -r requirements.txt
	$(PYTHON) -m pip install -r requirements.txt

test:      ## python3 -m pytest -v
	$(PYTHON) -m pytest -v

demo:      ## python3 demo.py
	$(PYTHON) demo.py

web:       ## python3 app.py   (opens http://localhost:8000)
	$(PYTHON) app.py

clean:
	rm -rf .pytest_cache __pycache__ blocksig/__pycache__ tests/__pycache__ results/*.md
