#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.test.base import BaseTest
from freeadi.core.client import ADClient


class TestADClient(BaseTest):
    """Test suite for ADClient"""

    def test_simple(self):
        if not self.online():
            return
        self.acquire_admin_credentials()
        domain = self.domain()
        client = ADClient(domain)
        result = client.search('(objectClass=user)')
        assert len(result) > 1
