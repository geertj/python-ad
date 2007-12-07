#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

from distutils.core import setup, Extension


setup(
    name = 'python-ad',
    version = '0.8',
    description = 'An AD client library for Python',
    author = 'Geert Jansen',
    author_email = 'geert@boskant.nl',
    url = 'http://www.boskant.nl/trac/python-ad',
    package_dir = {'': 'lib'},
    packages = ['ad', 'ad.core', 'ad.protocol', 'ad.util', 'ad.test'],
    ext_modules = [Extension('ad.protocol.krb5', ['lib/ad/protocol/krb5.c'],
                             libraries=['krb5'])]
)
