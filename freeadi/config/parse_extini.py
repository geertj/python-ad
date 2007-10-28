#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.config.parser import Parser


class ExtIniParser(Parser):
    """Extended INI config file parser.
    
    The extended INI format has support for subsections and is used e.g. by
    for the MIT Kerberos configuration file.
    """

    states = ( ('rvalue', 'exclusive'), )
    tokens = ( 'LBRACKET', 'RBRACKET', 'LBRACE', 'RBRACE',
               'EQUALS', 'STRING', 'WS', 'COMMENT')

    t_LBRACKET = r'\['
    t_RBRACKET = r'\]'
    t_RBRACE = r'\}'
    t_STRING = r'[a-zA-Z0-9_:./-]+'

    def t_COMMENT(self, t):
        r'\#.*' 
        pass  # no token

    def t_WS(self, t):
        r'[ \t\n]+'
        t.lexer.lineno += t.value.count('\n')
        pass  # no token

    def t_EQUALS(self, t):
        r'='
        t.lexer.begin('rvalue')
        return t

    def t_rvalue_LBRACE(self, t):
        r'\{'
        t.lexer.begin('INITIAL')
        return t

    def t_rvalue_WS(self, t):
        r'[ \t]+'
        pass  # no token

    def t_rvalue_STRING(self, t):
        r'[a-zA-Z0-9_:./-][^{}#\n]*'
        t.lexer.begin('INITIAL')
        t.value = t.value.rstrip()
        return t

    def _merge(self, cur, upd):
        """Merge two configuration (sub)sections. The dictionary `cur' is
        updated in-place with the contents of `upd'."""
        for key in upd:
            if key in cur:
                if isinstance(cur[key], basestring):
                    if isinstance(upd[key], basestring):
                        cur[key] = [cur[key], upd[key]]
                    elif isinstance(upd[key], list):
                        cur[key] = [cur[key]] + upd[key]
                    elif isinstance(upd[key], dict):
                        pass  # cannot merge
                elif isinstance(cur[key], list):
                    if isinstance(upd[key], basestring):
                        cur[key] += [upd[key]]
                    elif isinstance(upd[key], list):
                        cur[key] += upd[key]
                    elif isinstance(upd[key], dict):
                        pass  # cannot merge
                elif isinstance(cur[key], dict):
                    if isinstance(upd[key], basestring):
                        pass  # cannot merge
                    elif isinstance(upd[key], list):
                        pass  # cannot merge
                    elif isinstance(upd[key], dict):
                        self._merge(cur[key], upd[key])
            else:
                cur[key] = upd[key]
        return cur

    def p_input(self, p):
        """input : section
                 | section input
        """
        p[0] = p[1]
        if len(p) == 3:
            self._merge(p[0], p[2])

    def p_section(self, p):
        'section : section_head section_body'
        p[0] = { p[1] :  p[2] }

    def p_section_head(self, p):
        'section_head : LBRACKET STRING RBRACKET'
        p[0] = p[2]

    def p_section_body(self, p):
        """section_body : assignment
                        | assignment section_body
        """
        p[0] = p[1]
        if len(p) == 3:
            self._merge(p[0], p[2])

    def p_assignment(self, p):
        """assignment : STRING EQUALS STRING
                      | STRING EQUALS subsection"""
        p[0] = { p[1]: p[3] }

    def p_subsection(self, p):
        'subsection : LBRACE section_body RBRACE'
        p[0] = p[2]
