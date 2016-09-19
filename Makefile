all: sdist

sdist: test
	python setup.py sdist

pypi_upload:
	python setup.py register -r pypi
	python setup.py sdist upload -r pypi

pypitest_upload:
	python setup.py register -r pypitest
	python setup.py sdist upload -r pypitest

clean:
	rm -rf dist *.egg-info
	find nps/ -name "*.pyc" -exec rm -f {} \;

test:
	@echo "TODO:unit testing"
