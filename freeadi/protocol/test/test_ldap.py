#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.protocol import ldap


class TestLDAP(object):
    """Test suite for freeadi.util.ldap."""

    def test_encode_real_search_request(self):
        client = ldap.Client()
        filter = '(&(DnsDomain=FREEADI.ORG)(Host=magellan)(NtVer=\\06\\00\\00\\00))'
        req = client.create_search_request('', filter, ('NetLogon',),
                                          scope=ldap.SCOPE_BASE, msgid=4)
        fin = file('searchrequest.bin')
        buf = fin.read()
        fin.close()
        assert req == buf

    def test_decode_real_search_reply(self):
        client = ldap.Client()
        fin = file('searchresult.bin')
        buf = fin.read()
        fin.close()
        reply = client.parse_message_header(buf)
        assert reply == (4, 4)
        reply = client.parse_search_result(buf)
        assert len(reply) == 1
        msgid, dn, attrs = reply[0]
        assert msgid == 4
        assert dn == ''
        fin = file('netlogon.bin')
        netlogon = fin.read()
        fin.close()
        assert attrs == { 'netlogon': [netlogon] }
