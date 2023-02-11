#!/usr/bin/env python3

from setuptools import setup, find_packages

install_requires=[
   'lief'
]

setup(
    name='kextractor',
    version='1.0',
    packages=find_packages(),
    install_requires = install_requires,
    scripts=['scripts/kextractor'],
)
