#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

import os
import tempfile


class ConfigTest(object):
    """Base class for configuration file tests."""

    def dedent(self, s):
        lines = s.splitlines()
        for i in range(len(lines)):
            lines[i] = lines[i].lstrip()
        if lines and not lines[0]:
            lines = lines[1:]
        if lines and not lines[-1]:
            lines = lines[:-1]
        return '\n'.join(lines) + '\n'

    def tempfile(self):
        fd, name = tempfile.mkstemp()
        os.close(fd)
        self.c_tempfiles.append(name)
        return name

    def make_file(self, s):
        s = self.dedent(s)
        name = self.tempfile()
        fout = file(name, 'w')
        fout.write(s)
        fout.close()
        return name

    def setup_method(cls, method):
        cls.c_tempfiles = []

    def teardown_method(cls, method):
        for fname in cls.c_tempfiles:
            try:
                os.unlink(fname)
            except OSError:
                pass
        cls.c_tempfiles = []
