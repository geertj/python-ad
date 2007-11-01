#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import py.test
from freeadi.util import rfc1035


class TestRFC1035(object):
    """Test suite for util.rfc1035."""

    def decompress(self, s, offset):
        return rfc1035.decompress_rfc1035(s, offset)
 
    def test_simple(self):
        s = '\x03foo\x00'
        assert self.decompress(s, 0) == ('foo', 5)

    def test_multi_component(self):
        s = '\x03foo\x03bar\x00'
        assert self.decompress(s, 0) == ('foo.bar', 9)

    def test_pointer(self):
        s = '\x03foo\x00\xc0\x00'
        assert self.decompress(s, 5) == ('foo', 7)

    def test_forward_pointer(self):
        s = '\xc0\x02\x03foo\x00'
        assert self.decompress(s, 0) == ('foo', 2)

    def test_pointer_component(self):
        s = '\x03foo\x00\x03bar\xc0\x00'
        assert self.decompress(s, 5) == ('bar.foo', 11)

    def test_pointer_multi_component(self):
        s = '\x03foo\x03bar\x00\x03baz\xc0\x00'
        assert self.decompress(s, 9) == ('baz.foo.bar', 15)

    def test_multi_string(self):
        s = '\x03foo\x00\x03bar\x00'
        assert self.decompress(s, 0) == ('foo', 5)
        assert self.decompress(s, 5) == ('bar', 10)

    def test_null(self):
        s = '\x00'
        assert self.decompress(s, 0) == ('', 1)

    def test_error_null_input(self):
        s = ''
        py.test.raises(ValueError, self.decompress, s, 0)

    def test_error_missing_tag(self):
        s = '\x03foo'
        py.test.raises(ValueError, self.decompress, s, 0)

    def test_error_truncated_input(self):
        s = '\x04foo'
        py.test.raises(ValueError, self.decompress, s, 0)

    def test_error_pointer_overflow(self):
        s = '\xc0\x03'
        py.test.raises(ValueError, self.decompress, s, 0)

    def test_error_recursive_pointer(self):
        s = '\xc0\x00'
        py.test.raises(ValueError, self.decompress, s, 0)

    def test_error_illegal_tags(self):
        s = '\x80' + 0x80 * 'a' + '\x00'
        py.test.raises(ValueError, self.decompress, s, 0)
        s = '\x40' + 0x40 * 'a' + '\x00'
        py.test.raises(ValueError, self.decompress, s, 0)

    def test_error_half_pointer(self):
        s = '\xc0'
        py.test.raises(ValueError, self.decompress, s, 0)
