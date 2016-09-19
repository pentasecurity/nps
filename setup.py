#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Always prefer setuptools over distutils
from setuptools import setup, find_packages

# To use a consistent encoding
from codecs import open
from os import path
from distutils.core import setup
from distutils.command.install import install

import nps

SCRIPTS = ['bin/nps', 'bin/arp_mon']

# Get the long description from the README file
here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()

setup(
      name=nps.__NPS_MODULE_NAME__,
      packages=['nps', 'nps/tools'],
      scripts= SCRIPTS,
      version=nps.__NPS_VERSION__,
      description='network packet simulator',
      long_description=long_description,

      url='http://www.penatasecurity.com',
      author='morenice',
      author_email='hyounggu_lee@pentasecurity.com',
      license='MIT',

      classifiers=[
          # How mature is this project? Common values are
          #   3 - Alpha
          #   4 - Beta
          #   5 - Production/Stable
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: MIT License',
          'Topic :: Software Development',
          'Topic :: System :: Networking',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          ],
    )
