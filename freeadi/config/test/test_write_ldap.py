#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import py.test

from freeadi.config.exception import ConfigWriteError
from freeadi.config.write_ldap import LdapWriter
from freeadi.config.parse_ldap import LdapParser
from freeadi.config.test.support import ConfigTest


class TestWriteLdap(ConfigTest):
    """Test suite for LdapWriter."""

    def _test_roundtrip(self, conf):
        writer = LdapWriter()
        fio = file(self.tempfile(),'w+')
        writer.write(conf, fio)
        fio.seek(0)
        parser = LdapParser()
        res = parser.parse(fio)
        assert res == conf

    def test_simple(self):
        conf = { 'key_one': 'value1', 'key_two': 'value2' }
        self._test_roundtrip(conf)

    def test_multi_key(self):
        conf = { 'key_one': ['value1', 'value2'] }
        self._test_roundtrip(conf)

    def test_value_with_spaces(self):
        conf = { 'key_one': 'value with spaces' }
        self._test_roundtrip(conf)

    def _test_writer_raises_error(self, conf):
        writer = LdapWriter()
        fout = file(self.tempfile(), 'w')
        py.test.raises(ConfigWriteError, writer.write, conf, fout)

    def test_illegal_key(self):
        conf = { 'key*one': 'value1' }
        self._test_writer_raises_error(conf)

    def test_illegal_value_space(self):
        conf = { 'key_one': 'value ' }
        self._test_writer_raises_error(conf)

    def test_illegal_value_hash(self):
        conf = { 'key_one': 'value #' }
        self._test_writer_raises_error(conf)
