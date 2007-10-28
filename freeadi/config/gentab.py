#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.


# This script generates the PLY parser tables. Note: It needs to be run from
# the directory holding the parsers!!

from freeadi.config.parse_extini import ExtIniParser
from freeadi.config.parse_ldap import LdapParser

parser = ExtIniParser()
parser._write_parsetab()

parser = LdapParser()
parser._write_parsetab()
