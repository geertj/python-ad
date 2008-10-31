#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

from nose.tools import assert_raises
from ad.protocol import ldapfilter


class TestLDAPFilterParser(object):
    """Test suite for ad.protocol.ldapfilter."""

    def test_equals(self):
        filt = '(type=value)'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert isinstance(res, ldapfilter.EQUALS)
        assert res.type == 'type'
        assert res.value == 'value'

    def test_and(self):
        filt = '(&(type=value)(type2=value2))'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert isinstance(res, ldapfilter.AND)
        assert len(res.terms) == 2
        assert isinstance(res.terms[0], ldapfilter.EQUALS)
        assert isinstance(res.terms[1], ldapfilter.EQUALS)

    def test_and_multi_term(self):
        filt = '(&(type=value)(type2=value2)(type3=value3))'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert isinstance(res, ldapfilter.AND)
        assert len(res.terms) == 3
        assert isinstance(res.terms[0], ldapfilter.EQUALS)
        assert isinstance(res.terms[1], ldapfilter.EQUALS)
        assert isinstance(res.terms[2], ldapfilter.EQUALS)

    def test_or(self):
        filt = '(|(type=value)(type2=value2))'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert isinstance(res, ldapfilter.OR)
        assert len(res.terms) == 2
        assert isinstance(res.terms[0], ldapfilter.EQUALS)
        assert isinstance(res.terms[1], ldapfilter.EQUALS)

    def test_or_multi_term(self):
        filt = '(|(type=value)(type2=value2)(type3=value3))'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert isinstance(res, ldapfilter.OR)
        assert len(res.terms) == 3
        assert isinstance(res.terms[0], ldapfilter.EQUALS)
        assert isinstance(res.terms[1], ldapfilter.EQUALS)
        assert isinstance(res.terms[2], ldapfilter.EQUALS)

    def test_not(self):
        filt = '(!(type=value))'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert isinstance(res, ldapfilter.NOT)
        assert isinstance(res.term, ldapfilter.EQUALS)

    def test_lte(self):
        filt = '(type<=value)'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert isinstance(res, ldapfilter.LTE)
        assert res.type == 'type'
        assert res.value == 'value'

    def test_gte(self):
        filt = '(type>=value)'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert isinstance(res, ldapfilter.GTE)
        assert res.type == 'type'
        assert res.value == 'value'

    def test_approx(self):
        filt = '(type~=value)'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert isinstance(res, ldapfilter.APPROX)
        assert res.type == 'type'
        assert res.value == 'value'

    def test_present(self):
        filt = '(type=*)'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert isinstance(res, ldapfilter.PRESENT)
        assert res.type == 'type'

    def test_escape(self):
        filt = r'(type=\5c\00\2a)'
        parser = ldapfilter.Parser()
        res = parser.parse(filt)
        assert res.value == '\\\x00*'

    def test_error_incomplete_term(self):
        parser = ldapfilter.Parser()
        filt = '('
        assert_raises(ldapfilter.Error, parser.parse, filt)
        filt = '(type'
        assert_raises(ldapfilter.Error, parser.parse, filt)
        filt = '(type='
        assert_raises(ldapfilter.Error, parser.parse, filt)
        filt = '(type=)'
        assert_raises(ldapfilter.Error, parser.parse, filt)

    def test_error_not_multi_term(self):
        parser = ldapfilter.Parser()
        filt = '(!(type=value)(type2=value2))'
        assert_raises(ldapfilter.Error, parser.parse, filt)

    def test_error_illegal_operator(self):
        parser = ldapfilter.Parser()
        filt = '($(type=value)(type2=value2))'
        assert_raises(ldapfilter.Error, parser.parse, filt)

    def test_error_illegal_character(self):
        parser = ldapfilter.Parser()
        filt = '(type=val*e)'
        assert_raises(ldapfilter.Error, parser.parse, filt)
