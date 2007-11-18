#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import os.path
import py.test
import dns.resolver
from freeadi.test.base import BaseTest
from freeadi.protocol import netlogon


class TestDecoder(BaseTest):
    """Test suite for netlogon.Decoder."""

    def decode_uint32(self, buffer, offset):
        d = netlogon.Decoder()
        d.start(buffer)
        d._set_offset(offset)
        return d._decode_uint32(), d._offset()

    def test_uint32_simple(self):
        s = '\x01\x00\x00\x00'
        assert self.decode_uint32(s, 0) == (1, 4)

    def test_uint32_byte_order(self):
        s = '\x00\x01\x00\x00'
        assert self.decode_uint32(s, 0) == (0x100, 4)
        s = '\x00\x00\x01\x00'
        assert self.decode_uint32(s, 0) == (0x10000, 4)
        s = '\x00\x00\x00\x01'
        assert self.decode_uint32(s, 0) == (0x1000000, 4)

    def test_uint32_long(self):
        s = '\x00\x00\x00\xff'
        assert self.decode_uint32(s, 0) == (0xff000000L, 4)
        s = '\xff\xff\xff\xff'
        assert self.decode_uint32(s, 0) == (0xffffffffL, 4)

    def test_error_uint32_null_input(self):
        s = ''
        py.test.raises(netlogon.Error, self.decode_uint32, s, 0)

    def test_error_uint32_short_input(self):
        s = '\x00'
        py.test.raises(netlogon.Error, self.decode_uint32, s, 0)
        s = '\x00\x00'
        py.test.raises(netlogon.Error, self.decode_uint32, s, 0)
        s = '\x00\x00\x00'
        py.test.raises(netlogon.Error, self.decode_uint32, s, 0)

    def decode_rfc1035(self, buffer, offset):
        d = netlogon.Decoder()
        d.start(buffer)
        d._set_offset(offset)
        return d._decode_rfc1035(), d._offset()

    def test_rfc1035_simple(self):
        s = '\x03foo\x00'
        assert self.decode_rfc1035(s, 0) == ('foo', 5)

    def test_rfc1035_multi_component(self):
        s = '\x03foo\x03bar\x00'
        assert self.decode_rfc1035(s, 0) == ('foo.bar', 9)

    def test_rfc1035_pointer(self):
        s = '\x03foo\x00\xc0\x00'
        assert self.decode_rfc1035(s, 5) == ('foo', 7)

    def test_rfc1035_forward_pointer(self):
        s = '\xc0\x02\x03foo\x00'
        assert self.decode_rfc1035(s, 0) == ('foo', 2)

    def test_rfc1035_pointer_component(self):
        s = '\x03foo\x00\x03bar\xc0\x00'
        assert self.decode_rfc1035(s, 5) == ('bar.foo', 11)

    def test_rfc1035_pointer_multi_component(self):
        s = '\x03foo\x03bar\x00\x03baz\xc0\x00'
        assert self.decode_rfc1035(s, 9) == ('baz.foo.bar', 15)

    def test_rfc1035_pointer_recursive(self):
        s = '\x03foo\x00\x03bar\xc0\x00\x03baz\xc0\x05'
        assert self.decode_rfc1035(s, 11) == ('baz.bar.foo', 17)

    def test_rfc1035_multi_string(self):
        s = '\x03foo\x00\x03bar\x00'
        assert self.decode_rfc1035(s, 0) == ('foo', 5)
        assert self.decode_rfc1035(s, 5) == ('bar', 10)

    def test_rfc1035_null(self):
        s = '\x00'
        assert self.decode_rfc1035(s, 0) == ('', 1)

    def test_error_rfc1035_null_input(self):
        s = ''
        py.test.raises(netlogon.Error, self.decode_rfc1035, s, 0)

    def test_error_rfc1035_missing_tag(self):
        s = '\x03foo'
        py.test.raises(netlogon.Error, self.decode_rfc1035, s, 0)

    def test_error_rfc1035_truncated_input(self):
        s = '\x04foo'
        py.test.raises(netlogon.Error, self.decode_rfc1035, s, 0)

    def test_error_rfc1035_pointer_overflow(self):
        s = '\xc0\x03'
        py.test.raises(netlogon.Error, self.decode_rfc1035, s, 0)

    def test_error_rfc1035_cyclic_pointer(self):
        s = '\xc0\x00'
        py.test.raises(netlogon.Error, self.decode_rfc1035, s, 0)
        s = '\x03foo\xc0\x06\x03bar\xc0\x0c\x03baz\xc0\x00'
        py.test.raises(netlogon.Error, self.decode_rfc1035, s, 0)

    def test_error_rfc1035_illegal_tags(self):
        s = '\x80' + 0x80 * 'a' + '\x00'
        py.test.raises(netlogon.Error, self.decode_rfc1035, s, 0)
        s = '\x40' + 0x40 * 'a' + '\x00'
        py.test.raises(netlogon.Error, self.decode_rfc1035, s, 0)

    def test_error_rfc1035_half_pointer(self):
        s = '\xc0'
        py.test.raises(netlogon.Error, self.decode_rfc1035, s, 0)

    def test_io_byte(self):
        d = netlogon.Decoder()
        s = 'foo'
        d.start(s)
        assert d._read_byte() == 'f'
        assert d._read_byte() == 'o'
        assert d._read_byte() == 'o'

    def test_io_bytes(self):
        d = netlogon.Decoder()
        s = 'foo'
        d.start(s)
        assert d._read_bytes(3) == 'foo'

    def test_error_io_byte(self):
        d = netlogon.Decoder()
        s = 'foo'
        d.start(s)
        for i in range(3):
            d._read_byte()
        assert py.test.raises(netlogon.Error, d._read_byte)

    def test_error_io_bytes(self):
        d = netlogon.Decoder()
        s = 'foo'
        d.start(s)
        assert py.test.raises(netlogon.Error, d._read_bytes, 4)

    def test_error_io_bounds(self):
        d = netlogon.Decoder()
        s = 'foo'
        d.start(s)
        d._set_offset(4)
        assert py.test.raises(netlogon.Error, d._read_byte)
        assert py.test.raises(netlogon.Error, d._read_bytes, 4)

    def test_error_negative_offset(self):
        d = netlogon.Decoder()
        s = 'foo'
        d.start(s)
        assert py.test.raises(netlogon.Error, d._set_offset, -1)

    def test_error_io_type(self):
        d = netlogon.Decoder()
        assert py.test.raises(netlogon.Error, d.start, 1)
        assert py.test.raises(netlogon.Error, d.start, 1L)
        assert py.test.raises(netlogon.Error, d.start, ())
        assert py.test.raises(netlogon.Error, d.start, [])
        assert py.test.raises(netlogon.Error, d.start, {})
        assert py.test.raises(netlogon.Error, d.start, u'test')

    def test_real_packet(self):
        fname = os.path.join(self.basedir(), 'freeadi/protocol/test',
                             'netlogon.bin')
        fin = file(fname)
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


class TestClient(BaseTest):
    """Test suite for netlogon.Client."""

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
