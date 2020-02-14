VIRTUALENV = $(shell which virtualenv)
# Prefer python3
PYTHONEXEC := $(shell if which python3 &>/dev/null ; then echo "python3" ; else echo "python2" ; fi)

VERSION = `grep VERSION src/version.py | cut -d \' -f2`

bandit: pydeps
	. venv/bin/activate; bandit -r src/

clean:
	rm -rf *.egg-info/
	rm -rf .cache/
	rm -rf .tox/
	rm -rf .coverage
	rm -rf build
	rm -rf dist
	rm -rf htmlcov
	rm -rf venv
	find . -type d -name '__pycache__' | xargs rm -rf
	find . -name "*.pyc" -type f -print0 | xargs -0 /bin/rm -rf

compile:
	. venv/bin/activate; python setup.py build install

console:
	. venv/bin/activate; python

coverage:
	. venv/bin/activate; coverage html
	. venv/bin/activate; coverage report

current:
	@echo $(VERSION)

deps: venv
	. venv/bin/activate; python -m pip install --upgrade -qr requirements.txt

install: clean venv deps
	. venv/bin/activate; python setup.py install

inspectortiger: pydeps
	. venv/bin/activate; inspectortiger src/

lint: pydeps
	. venv/bin/activate; python -m flake8 src/

preflight: bandit inspectortiger coverage test

pydeps: deps
	. venv/bin/activate; pip install --upgrade -q pip flake8 bandit \
	  pyre-check coverage pytest pytest-mock pytest-cov pytest-runner \
	  mock minimock faker responses inspectortiger

test: lint
	. venv/bin/activate; py.test --cov=src tests -r w --capture=sys --cov-fail-under 99 -vv

tox:
	. venv/bin/activate; tox

venv:
	mkdir venv
	$(VIRTUALENV) -p $(PYTHONEXEC) venv
