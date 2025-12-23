# Variables
APP = PM4.py
VENV = venv
REQS = requirements.txt

# Setup virtual environment
venv:
	@echo "Creating virtual environment..."
	python3 -m venv $(VENV)

# Install requirements for venv
install: venv
	$(VENV)/bin/pip install -r $(REQS)

# Run PM app
run:
	@echo "Running Pixel Mask App..."
	$(VENV)/bin/python $(APP)