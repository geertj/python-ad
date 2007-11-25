#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

import re
from ad.util.parser import Parser as PLYParser


class Error(Exception):
    """LDAP Filter exception"""


class AND(object):

    def __init__(self, *terms):
        self.terms = terms

class OR(object):

    def __init__(self, *terms):
        self.terms = terms

class NOT(object):

    def __init__(self, term):
        self.term = term

class EQUALS(object):

    def __init__(self, type, value):
        self.type = type
        self.value = value

class LTE(object):

    def __init__(self, type, value):
        self.type = type
        self.value = value

class GTE(object):

    def __init__(self, type, value):
        self.type = type
        self.value = value

class APPROX(object):

    def __init__(self, type, value):
        self.type = type
        self.value = value

class PRESENT(object):

    def __init__(self, type):
        self.type = type


class Parser(PLYParser):
    """A parser for LDAP filters (see RFC2254).

    The parser is pretty complete. Currently lacking are substring matches and
    extensible matches.
    """

    exception = Error
    tokens = ('LPAREN', 'RPAREN', 'EQUALS', 'AND', 'OR', 'NOT',
              'LTE','GTE', 'APPROX', 'PRESENT', 'STRING')

    t_LPAREN = r'\('
    t_RPAREN = r'\)'
    t_EQUALS = r'='
    t_AND = r'&'
    t_OR = r'\|'
    t_NOT = r'!'
    t_LTE = r'<='
    t_GTE = r'>='
    t_APPROX = r'~='
    t_PRESENT = r'=\*'

    re_escape = re.compile(r'\\([0-9a-fA-F]{2})')

    def _unescape(self, value):
        """Unescape a hex encoded string."""
        pos = 0
        parts = []
        while True:
            mobj = self.re_escape.search(value, pos)
            if not mobj:
                parts.append(value[pos:])
                break
            parts.append(value[pos:mobj.start()])
            ch = chr(int(mobj.group(1), 16))
            parts.append(ch)
            pos = mobj.end()
        result = ''.join(parts)
        return result

    def t_STRING(self, t):
        r'[^()=&|!<>~*]+'
        t.value = self._unescape(t.value)
        return t

    def p_filter(self, p):
        """filter : LPAREN and RPAREN
                  | LPAREN or RPAREN
                  | LPAREN not RPAREN
                  | LPAREN item RPAREN
        """
        p[0] = p[2]

    def p_and(self, p):
        'and : AND filterlist'
        p[0] = AND(*p[2])

    def p_or(self, p):
        'or : OR filterlist'
        p[0] = OR(*p[2])

    def p_not(self, p):
        'not : NOT filter'
        p[0] = NOT(p[2])

    def p_filterlist(self, p):
        """filterlist : filter
                      | filter filterlist
        """
        if len(p) == 2:
            p[0] = (p[1],)
        else:
            p[0] = (p[1],) + p[2]

    def p_item(self, p):
        """item : STRING EQUALS STRING
                | STRING LTE STRING
                | STRING GTE STRING
                | STRING APPROX STRING
                | STRING PRESENT
        """
        if p[2] == '=':
            p[0] = EQUALS(p[1], p[3])
        elif p[2] == '<=':
            p[0] = LTE(p[1], p[3])
        elif p[2] == '>=':
            p[0] = GTE(p[1], p[3])
        elif p[2] == '~=':
            p[0] = APPROX(p[1], p[3])
        elif p[2] == '=*':
            p[0] = PRESENT(p[1])
