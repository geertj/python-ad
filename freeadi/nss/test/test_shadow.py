#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

import os
from freeadi.nss.shadow import ShadowNamingService


class TestShadowNS(object):

    disabled = not not os.getuid()

    def test_compare_etc_shadow(self):
        fin = file('/etc/shadow')
        lines = [ line.strip() for line in fin ]
        ns = ShadowNamingService('files')
        entries = [ str(entry) for entry in ns ]
        # empty values are returned as -1
        entries = [ entry.replace(':-1', ':') for entry in entries ]
        assert lines[0] == entries[0]
