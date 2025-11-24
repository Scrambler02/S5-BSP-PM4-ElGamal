PYTHON = python3
SCRIPT = PM3_UI.py

run: 
		$(PYTHON) $(SCRIPT)

clean: 
		rm -f *.pyc