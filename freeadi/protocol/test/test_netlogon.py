#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import py.test
from freeadi.protocol import netlogon


class TestNetlogon(object):
    """Test suite for netlogon parser."""

    def test_real_packet(self):
        fin = file('netlogon.bin')
        buf = fin.read()
        fin.close()
        dec = netlogon.Decoder()
        dec.start(buf)
        res = dec.parse()
        assert res[0] == 'freeadi.org'
        assert res[1] == 'freeadi.org'
        assert res[2] == 'Default-First-Site'
        assert res[3] == 'Test-Site'

    def test_error_short_input(self):
        buf = 'x' * 24
        dec = netlogon.Decoder()
        dec.start(buf)
        py.test.raises(netlogon.Error, dec.parse)
