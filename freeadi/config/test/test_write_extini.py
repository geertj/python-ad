#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import py.test

from freeadi.config.exception import ConfigWriteError
from freeadi.config.write_extini import ExtIniWriter
from freeadi.config.parse_extini import ExtIniParser
from freeadi.config.test.support import ConfigTest


class TestWriteExtIni(ConfigTest):
    """Test suite for ExtIniWriter."""

    def _test_roundtrip(self, conf):
        writer = ExtIniWriter()
        fio = file(self.tempfile(),'w+')
        writer.write(conf, fio)
        fio.seek(0)
        parser = ExtIniParser()
        res = parser.parse(fio)
        assert res == conf

    def test_simple(self):
        conf = { 'section1': { 'key1': 'value1', 'key2': 'value2' } }
        self._test_roundtrip(conf)

    def test_multi_section(self):
        conf = { 'section1': { 'key1': 'value1' },
                 'section2': { 'key2': 'value2'  } }
        self._test_roundtrip(conf)

    def test_multi_key(self):
        conf = { 'section1': { 'key1': ['value1', 'value2'] } }
        self._test_roundtrip(conf)

    def test_subsection(self):
        conf = { 'section1': { 'key1': { 'key2': 'value2' } } }
        self._test_roundtrip(conf)

    def test_value_with_spaces(self):
        conf = { 'section1': { 'key1': 'value with spaces' } }
        self._test_roundtrip(conf)

    def _test_writer_raises_error(self, conf):
        writer = ExtIniWriter()
        fout = file(self.tempfile(), 'w')
        py.test.raises(ConfigWriteError, writer.write, conf, fout)

    def test_illegal_section(self):
        conf = { 's*ction': { 'key': 'value' } }
        self._test_writer_raises_error(conf)

    def test_illegal_key(self):
        conf = { 'section1': { 'k*y': 'value' } }
        self._test_writer_raises_error(conf)

    def test_illegal_value(self):
        conf = { 'section1': { 'key': 'value }' } }
        self._test_writer_raises_error(conf)

    def test_illegal_subsection(self):
        conf = { 'section1': { 'k*y1': { 'key2': 'value2' } } }
        self._test_writer_raises_error(conf)
