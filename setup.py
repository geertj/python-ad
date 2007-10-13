#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

from distutils import setup


setup(
    name = 'FreeADI',
    version = '0.5',
    description = 'A free AD interface for Linux',
    author = 'Geert Jansen',
    author_email = 'geert@boskant.nl',
    url = 'http://www.boskant.nl/trac/freeadi',

    packages = ['freeadi', 'freeadi.core', 'freeadi.config',
                'freeadi.command', 'freeadi.system'],
    scripts = ['scripts/freeadi.py'],
    data_files = { 'templates': 'templates/*.tmpl',
                   '/etc': ['config/freeadi.conf'] }
)
