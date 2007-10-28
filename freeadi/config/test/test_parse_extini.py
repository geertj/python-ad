#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import py.test

from freeadi.config.exception import ConfigParseError
from freeadi.config.parse_extini import ExtIniParser
from freeadi.config.test.support import ConfigTest


class TestParseExtIni(ConfigTest):
    """Test suite for ExtIniParser."""

    def test_simple_string(self):
        conf = """
            [section1]
            key1 = value1
            key2 = value2
            """
        parser = ExtIniParser()
        res = parser.parse(conf)
        assert 'section1' in res
        assert isinstance(res['section1'], dict)
        assert 'key1' in res['section1']
        assert isinstance(res['section1']['key1'], basestring)
        assert res['section1']['key1'] == 'value1'
        assert 'key2' in res['section1']
        assert isinstance(res['section1']['key2'], basestring)
        assert res['section1']['key2'] == 'value2'

    def test_simple_stream(self):
        conf = """
            [section1]
            key1 = value1
            key2 = value2
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        res = parser.parse(fin)
        assert 'section1' in res
        assert isinstance(res['section1'], dict)
        assert 'key1' in res['section1']
        assert isinstance(res['section1']['key1'], basestring)
        assert res['section1']['key1'] == 'value1'
        assert 'key2' in res['section1']
        assert isinstance(res['section1']['key2'], basestring)
        assert res['section1']['key2'] == 'value2'

    def test_multi_section(self):
        conf = """
            [section1]
            key1 = value1
            [section2]
            key2 = value2
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        res = parser.parse(fin)
        assert 'section1' in res
        assert 'key1' in res['section1']
        assert 'key2' not in res['section1']
        assert res['section1']['key1'] == 'value1'
        assert 'section2' in res
        assert 'key2' in res['section2']
        assert 'key1' not in res['section2']
        assert res['section2']['key2'] == 'value2'

    def test_multi_value(self):
        conf = """
            [section1]
            key1 = value1
            key1 = value2
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        res = parser.parse(fin)
        assert isinstance(res['section1']['key1'], list)
        assert res['section1']['key1'] == ['value1', 'value2']

    def test_subsection(self):
        conf = """
            [section1]
            key1 = {
              key2 = value2
              key3 = value3
            }
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        res = parser.parse(fin)
        assert isinstance(res['section1']['key1'], dict)
        d = res['section1']['key1']
        assert d['key2'] == 'value2'
        assert d['key3'] == 'value3'

    def test_subsection_merge(self):
        conf = """
            [section1]
            key1 = value1
            [section1]
            key2 = value2
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        res = parser.parse(fin)
        assert 'section1' in res
        assert 'key1' in res['section1']
        assert res['section1']['key1'] == 'value1'
        assert 'key2' in res['section1']
        assert res['section1']['key2'] == 'value2'

    def test_subsection_merge_list(self):
        conf = """
            [section1]
            key1 = value1
            [section1]
            key1 = value2
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        res = parser.parse(fin)
        assert isinstance(res['section1']['key1'], list)
        assert res['section1']['key1'] == ['value1', 'value2']

    def test_subsection_merge_dict(self):
        conf = """
            [section1]
            key1 = {
                key2 = value2
            }
            [section1]
            key1 = {
                key3 = value3
            }
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        res = parser.parse(fin)
        assert isinstance(res['section1']['key1'], dict)
        assert res['section1']['key1'] == { 'key2': 'value2', 'key3': 'value3' }

    def test_lex_error_simple(self):
        conf = """
            [section1]
            k*y = value
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        py.test.raises(ConfigParseError, parser.parse, fin)

    def test_lex_error_info(self):
        conf = """
            [section1]
            k*y = value
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        try:
            parser.parse(fin)
        except ConfigParseError, err:
            err = err
        assert hasattr(err, 'fname')
        assert isinstance(err.fname, basestring)
        assert hasattr(err, 'lineno')
        assert isinstance(err.lineno, int)
        assert err.lineno == 2
        assert hasattr(err, 'column')
        assert isinstance(err.column, int)
        assert err.column == 2

    def test_syntax_error_simple(self):
        conf = """
            key = value
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        py.test.raises(ConfigParseError, parser.parse, fin)

    def test_syntax_error_info(self):
        conf = """
            key = value
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        try:
            parser.parse(fin)
        except ConfigParseError, err:
            err = err
        assert hasattr(err, 'fname')
        assert isinstance(err.fname, basestring)
        assert hasattr(err, 'lineno')
        assert isinstance(err.lineno, int)
        assert err.lineno == 1
        assert hasattr(err, 'column')
        assert isinstance(err.column, int)
        assert err.column == 1

    def test_comment(self):
        conf = """
            # comment 1
            [section1]
            key = value  # comment 2
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        res = parser.parse(fin)
        assert res['section1']['key'] == 'value'

    def test_value_with_spaces(self):
        conf = """
            [section1]
            key = value with spaces
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        res = parser.parse(fin)
        assert res['section1']['key'] == 'value with spaces'

    def test_value_with_spaces_and_comment(self):
        conf = """
            [section1]
            key = value with spaces  # comment
            """
        fin = file(self.make_file(conf))
        parser = ExtIniParser()
        res = parser.parse(fin)
        assert res['section1']['key'] == 'value with spaces'
