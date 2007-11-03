#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.util.parser import Parser


class LdapParser(Parser):
    """Parser for ldap.conf (nss_ldap and OpenLDAP configuration files)."""

    states = ( ('rhs', 'inclusive'), )
    tokens = ( 'WS', 'COMMENT', 'KEY', 'VALUE', 'EOL' )

    def t_WS(self, t):
        r'[ \t\n]+'
        pass  # no token

    def t_COMMENT(self, t):
        r'\#[^\n]*'
        pass  # no token

    def t_KEY(self, t):
        r'[a-zA-Z_]+'
        t.lexer.begin('rhs')
        return t

    def t_rhs_WS(self, t):
        r'[ \t]+'
        pass  # no token

    def t_rhs_VALUE(self, t):
        r'[a-zA-Z0-9_:./-].*?(?=[ \t]*[#\n])'
        return t

    def t_rhs_EOL(self, t):
        r'\n'
        t.lexer.begin('INITIAL')
        return t

    def _merge(self, cur, upd):
        """Merge two assignments. The dictionary `cur' is updated in-place
        with the contents of `upd'."""
        for key in upd:
            if key in cur:
                if isinstance(cur[key], basestring):
                    if isinstance(upd[key], basestring):
                        cur[key] = [cur[key], upd[key]]
                    elif isinstance(upd[key], list):
                        cur[key] = [cur[key]] + upd[key]
                elif isinstance(cur[key], list):
                    if isinstance(upd[key], basestring):
                        cur[key] += [upd[key]]
                    elif isinstance(upd[key], list):
                        cur[key] += upd[key]
            else:
                cur[key] = upd[key]
        return cur

    def p_input(self, p):
        """input : assignment
                 | assignment input
        """
        p[0] = p[1]
        if len(p) == 3:
            self._merge(p[0], p[2])

    def p_assignment(self, p):
        """assignment : KEY VALUE EOL"""
        p[0] = { p[1]: p[2] }
