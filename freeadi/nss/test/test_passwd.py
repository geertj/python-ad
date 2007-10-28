#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.nss.passwd import PasswdNamingService


class TestPasswdNS(object):

    def test_compare_etc_passwd(self):
        fin = file('/etc/passwd')
        lines = [ line.strip() for line in fin ]
        ns = PasswdNamingService('files')
        entries = [ str(entry) for entry in ns ]
        assert lines == entries
