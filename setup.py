#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from distutils.core import setup, Extension


setup(
    name = 'FreeADI',
    version = '0.5',
    description = 'A free AD interface for Linux',
    author = 'Geert Jansen',
    author_email = 'geert@boskant.nl',
    url = 'http://www.boskant.nl/trac/freeadi',

    packages = ['freeadi', 'freeadi.core', 'freeadi.config',
                'freeadi.protocol', 'freeadi.system', 'freeadi.util'],
    ext_modules = [Extension('freeadi.core.krb5', ['freeadi/core/krb5.c'],
                             libraries=['krb5'])],
    data_files = { 'templates': 'templates/*.tmpl',
                   '/etc': ['config/freeadi.conf'] }
)
