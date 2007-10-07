#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

from parse_ldap import LdapParser
from write_ldap import LdapWriter
from config import Config


class LdapConfig(Config):
    """nss_ldap/OpenLDAP configuration file access."""

    def __init__(self):
        super(LdapConfig, self).__init__(LdapParser, LdapWriter)
