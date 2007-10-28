#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import py.test

from freeadi.config.parse_ldap import LdapParser
from freeadi.config.exception import ConfigParseError
from freeadi.config.test.support import ConfigTest


class TestLdapParser(ConfigTest):
    """Test suite for LdapParser."""

    def test_simple_string(self):
        conf = """
            key_one value1
            key_two value2
            """
        parser = LdapParser()
        res = parser.parse(conf)
        assert 'key_one' in res
        assert res['key_one'] == 'value1'
        assert 'key_two' in res
        assert res['key_two'] == 'value2'

    def test_simple_stream(self):
        conf = """
            key_one value1
            key_two value2
            """
        fin = file(self.make_file(conf))
        parser = LdapParser()
        res = parser.parse(fin)
        assert 'key_one' in res
        assert res['key_one'] == 'value1'
        assert 'key_two' in res
        assert res['key_two'] == 'value2'

    def test_multi_value(self):
        conf = """
            key_one value1
            key_one value2
            """
        fin = file(self.make_file(conf))
        parser = LdapParser()
        res = parser.parse(fin)
        assert 'key_one' in res
        assert res['key_one'] == ['value1', 'value2']

    def test_lex_error_simple(self):
        conf = """
            key*one value1
            """
        fin = file(self.make_file(conf))
        parser = LdapParser()
        py.test.raises(ConfigParseError, parser.parse, fin)

    def test_lex_error_info(self):
        conf = """
            key*one value1
            """
        fin = file(self.make_file(conf))
        parser = LdapParser()
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
        assert err.column == 4

    def test_parse_error_simple(self):
        conf = """
            key_one
            """
        fin = file(self.make_file(conf))
        parser = LdapParser()
        py.test.raises(ConfigParseError, parser.parse, fin)

    def test_parse_error_info(self):
        conf = """
            key_one
            """
        fin = file(self.make_file(conf))
        parser = LdapParser()
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
        assert err.column == 8

    def test_comment(self):
        conf = """
            # comment
            key_one value1  # comment
            """
        fin = file(self.make_file(conf))
        parser = LdapParser()
        res = parser.parse(fin)
        assert 'key_one' in res
        assert res['key_one'] == 'value1'

    def test_value_with_spaces(self):
        conf = """
            key_one value with spaces
            """
        fin = file(self.make_file(conf))
        parser = LdapParser()
        res = parser.parse(fin)
        assert 'key_one' in res
        assert res['key_one'] == 'value with spaces'

    def test_value_with_spaces_and_comment(self):
        conf = """
            key_one value with spaces  # comment
            """
        fin = file(self.make_file(conf))
        parser = LdapParser()
        res = parser.parse(fin)
        assert 'key_one' in res
        assert res['key_one'] == 'value with spaces'
