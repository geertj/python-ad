#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import py.test
import dns.resolver
from freeadi.test.base import BaseTest
from freeadi.protocol import netlogon


class TestNetlogon(BaseTest):
    """Test suite for netlogon parser."""

    def test_real_packet(self):
        fin = file('netlogon.bin')
        buf = fin.read()
        fin.close()
        dec = netlogon.Decoder()
        dec.start(buf)
        res = dec.parse()
        assert res.forest == 'freeadi.org'
        assert res.domain == 'freeadi.org'
        assert res.client_site == 'Default-First-Site'
        assert res.server_site == 'Test-Site'

    def test_error_short_input(self):
        buf = 'x' * 24
        dec = netlogon.Decoder()
        dec.start(buf)
        py.test.raises(netlogon.Error, dec.parse)

    def test_online(self):
        if not self.online():
            return
        domain = self.domain()
        client = netlogon.Client()
        answer = dns.resolver.query('_ldap._tcp.%s' % domain, 'SRV')
        addrs = [ (ans.target.to_text(), ans.port) for ans in answer ]
        names = [ ans.target.to_text().rstrip('.') for ans in answer ]
        for addr in addrs:
            client.query(addr, domain)
        result = client.call()
        assert len(result) == len(addrs)  # assume retries are succesful
        for res in result:
            assert res.type in (23,)
            assert res.flags & netlogon.SERVER_LDAP
            assert res.flags & netlogon.SERVER_KDC
            assert res.flags & netlogon.SERVER_WRITABLE
            assert len(res.domain_guid) == 16
            assert len(res.forest) > 0
            assert res.domain == domain
            assert res.hostname in names
            assert len(res.netbios_domain) > 0
            assert len(res.netbios_hostname) > 0
            assert len(res.client_site) > 0
            assert len(res.server_site) > 0
            assert res.timing >= 0.0
