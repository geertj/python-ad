#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import re
import time
import socket

from freeadi.util.writer import Writer
from freeadi.config.exception import ConfigWriteError
from freeadi.config.parse_extini import ExtIniParser


class ExtIniWriter(Writer):
    """Writer for an extended INI config file."""

    re_string = re.compile('^' + ExtIniParser.t_STRING + '$')
    re_rvalue_string = re.compile('^' + ExtIniParser.t_rvalue_STRING.__doc__ + '$')

    def _write_section_header(self, section, fout, indent=''):
        fout.write('\n[%s]\n' % section)

    def _write_section_body(self, body, fout, indent=''):
        indent += '  '
        for key in body:
            value = body[key]
            if isinstance(value, dict):
                fout.write('%s%s = {\n' % (indent, key))
                self._write_section_body(value, fout, indent)
                fout.write('%s}\n' % indent)
            elif isinstance(value, list):
                for val in value:
                    fout.write('%s%s = %s\n' % (indent, key, val))
            else:
                if not self.re_rvalue_string.match(value):
                    raise ConfigWriteError, 'Illegal value string: %s' % value
                fout.write('%s%s = %s\n' % (indent, key, value))

    def _check_input(self, data):
        for section in data:
            if not self.re_string.match(section):
                raise ConfigWriteError, 'Illegal section name: %s' % section
            self._check_section(data[section])

    def _check_section(self, section):
        for key in section:
            if not self.re_string.match(key):
                raise ConfigWriteError, 'Illegal key name: %s' % key
            value = section[key]
            if isinstance(value, basestring):
                if not self.re_rvalue_string.match(value):
                    raise ConfigWriteError, 'Illegal key value: %s' % value
            elif isinstance(value, list):
                for val in value:
                    if not self.re_rvalue_string.match(val):
                        raise ConfigWriteError, 'Illegal key value: %s' % value
            elif isinstance(value, dict):
                self._check_section(value)

    def write(self, data, fout):
        """Write krb5.conf `data' to stream `fout'."""
        self._check_input(data)
        for section in data:
            self._write_section_header(section, fout)
            self._write_section_body(data[section], fout)
