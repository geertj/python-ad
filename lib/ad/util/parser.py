#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

import sys
import os.path

from ply import lex, yacc


class Parser(object):
    """Wrapper object for PLY lexer/parser."""

    exception = ValueError

    def _parsetab_name(cls, fullname=True):
        """Return a name for PLY's parsetab file."""
        ptname = sys.modules[cls.__module__].__name__ + '_tab'
        if not fullname:
            ptname = ptname.split('.')[-1]
        return ptname

    _parsetab_name = classmethod(_parsetab_name)

    def _write_parsetab(cls):
        """Write parser table (distribution purposes)."""
        parser = cls()
        tabname = cls._parsetab_name(False)
        yacc.yacc(module=parser, debug=0, tabmodule=tabname)

    _write_parsetab = classmethod(_write_parsetab)

    def parse(self, input, fname=None):
        lexer = lex.lex(object=self)
        if hasattr(input, 'read'):
            input = input.read()
        lexer.input(input)
        self.m_input = input
        self.m_fname = fname
        parser = yacc.yacc(module=self, debug=0,
                           tabmodule=self._parsetab_name())
        parsed = parser.parse(lexer=lexer, tracking=True)
        return parsed

    def _position(self, o):
        if hasattr(o, 'lineno') and hasattr(o, 'lexpos'):
            lineno = o.lineno
            lexpos = o.lexpos
            pos = self.m_input.rfind('\n', 0, lexpos)
            column = lexpos - pos
        else:
            lineno = None
            column = None
        return lineno, column

    def t_ANY_error(self, t):
        err = self.exception()
        msg = 'illegal token'
        if self.m_fname:
            err.fname = self.m_fname
            msg += ' in file %s' % self.m_fname
            lineno, column = self._position(t)
            if lineno is not None and column is not None:
                msg += ' at %d:%d' % (lineno, column)
                err.lineno = lineno
                err.column = column
        err.message = msg
        raise err

    def p_error(self, p):
        err = self.exception()
        msg = 'syntax error'
        if self.m_fname:
            err.fname = self.m_fname
            msg += ' in file %s' % self.m_fname
            lineno, column = self._position(p)
            if lineno is not None and column is not None:
                msg += ' at %d:%d' % (lineno, column)
                err.lineno = lineno
                err.column = column
        err.message = msg
        raise err
