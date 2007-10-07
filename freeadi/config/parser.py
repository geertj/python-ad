#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

import sys
import os.path

from ply import lex, yacc
from freeadi.config.exception import ConfigParseError


class Parser(object):
    """Wrapper object for PLY lexer/parser."""

    @classmethod
    def _parsetab_name(cls, fullname=True):
        """Return a name for PLY's parsetab file."""
        ptname = sys.modules[cls.__module__].__file__
        ptname = os.path.basename(ptname)
        ptname = os.path.splitext(ptname)[0] + '_tab'
        if fullname:
            ptname = 'freeadi.config.%s' % ptname
        return ptname

    @classmethod
    def _write_parsetab(cls):
        """Write parser table (distribution purposes)."""
        parser = cls()
        tabname = cls._parsetab_name(False)
        yacc.yacc(module=parser, debug=0, tabmodule=tabname)

    def parse(self, input, fname=None):
        lexer = lex.lex(object=self)
        if hasattr(input, 'read'):
            input = input.read()
        lexer.input(input)
        self.m_input = input
        self.m_fname = fname or '<unknown>'
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
        m = 'illegal token in file %s' % self.m_fname
        lineno, column = self._position(t)
        if lineno is not None and column is not None:
            m += ' at %d:%d' % (lineno, column)
        err = ConfigParseError(m)
        err.fname = self.m_fname
        err.lineno = lineno
        err.column = column
        raise err

    def p_error(self, p):
        m = 'syntax error in file %s' % self.m_fname
        lineno, column = self._position(p)
        if lineno is not None and column is not None:
            m += ' at %d:%d' % (lineno, column)
        err = ConfigParseError(m)
        err.fname = self.m_fname
        err.lineno = lineno
        err.column = column
        raise err
