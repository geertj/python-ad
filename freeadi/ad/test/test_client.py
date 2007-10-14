#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

from freeadi.test.base import FreeADITest
from freeadi.ad.client import ADClient


class TestADClient(FreeADITest):
    """Test suite for ADClient"""

    def test_simple(self):
        if not self.online_enabled():
            return
        self.acquire_admin_credentials()
        domain = self.config().get('test', 'domain')
        print 'domain', domain
        client = ADClient(domain)
        result = client.search('(objectClass=user)')
        assert len(result) > 1
