#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007-2009 by the Python-AD authors. See the
# file "AUTHORS" for a complete overview.

import ldap
import ldap.dn

# ldap.str2dn has been removed in python-ldap >= 2.3.6. We now need to use
# the version in ldap.dn.
try:
    str2dn = ldap.dn.str2dn
except AttributeError:
    str2dn = ldap.str2dn
