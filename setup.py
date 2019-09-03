#!/usr/bin/env python
# -*- encoding: utf-8 -*- #

# This file is copied from Network Process Monitor.
#
# Network Process Monitor is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Network Process Monitor is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Printrun.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name = 'netprocmon',
    version = '0.0.1rc7',
    description = 'Network Process Monitor is a Python API to monitor process traffic',
    long_description = long_description,
    url = 'https://pypi.python.org/pypi/netprocmon',
    author = 'Henrik Ankersoe',
    author_email = 'henrik@diblo.dk',
    license = 'GPL v3',
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        "Topic :: Software Development :: Libraries :: Python Modules",
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 2.7'
    ],
    packages = find_packages(exclude=['tests*'])
)

