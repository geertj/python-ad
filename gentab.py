#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

import os

# This script generates the PLY parser tables. Note: It needs to be run from
# the top-level python-ad directory!

from ad.protocol.ldapfilter import Parser as LDAPFilterParser

os.chdir('lib/ad/protocol')

parser = LDAPFilterParser()
parser._write_parsetab()
