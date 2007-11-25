#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

import os.path
from ad.test.base import BaseTest
from ad.protocol import ldap


class TestLDAP(BaseTest):
    """Test suite for ad.util.ldap."""

    def test_encode_real_search_request(self):
        client = ldap.Client()
        filter = '(&(DnsDomain=FREEADI.ORG)(Host=magellan)(NtVer=\\06\\00\\00\\00))'
        req = client.create_search_request('', filter, ('NetLogon',),
                                          scope=ldap.SCOPE_BASE, msgid=4)
        fname = os.path.join(self.basedir(), 'lib/ad/protocol/test',
                             'searchrequest.bin')
        fin = file(fname)
        buf = fin.read()
        fin.close()
        assert req == buf

    def test_decode_real_search_reply(self):
        client = ldap.Client()
        fname = os.path.join(self.basedir(), 'lib/ad/protocol/test',
                             'searchresult.bin')
        fin = file(fname)
        buf = fin.read()
        fin.close()
        reply = client.parse_message_header(buf)
        assert reply == (4, 4)
        reply = client.parse_search_result(buf)
        assert len(reply) == 1
        msgid, dn, attrs = reply[0]
        assert msgid == 4
        assert dn == ''
        fname = os.path.join(self.basedir(), 'lib/ad/protocol/test',
                             'netlogon.bin')
        fin = file(fname)
        netlogon = fin.read()
        fin.close()
        assert attrs == { 'netlogon': [netlogon] }
