#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

import os
import re
from freeadi import FreeADIError


class FreeADIConfig(dict):
    """FreeADI configuration file object."""

    _instance = None
    _fname = '/etc/sysconfig/freeadi'

    re_comment = re.compile('^(|\s*#.*)$')
    re_assign = re.compile('^([a-zA-Z0-9_]+)="([^"]+)"$')

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = FreeADIConfig()
        return cls._instance

    def read(self, fname=None):
        if fname is None:
            fname = self._fname
        fin = file(fname)
        try:
            for line in fin:
                line = line.strip()
                mobj = self.re_comment.match(line)
                if mobj:
                    continue
                mobj = self.re_assign.match(line)
                if mobj:
                    self[mobj.group(1)] = mobj.group(2)
                    continue
                raise FreeADIError, 'Illegal configuration file syntax.'
        finally:
            fin.close()

    def write(self, fname=None):
        """Write the config file."""
        if fname is None:
            fname = self._fname
        # We write the config file in such a way as to preserve any formatting
        # as much as possible.
        fin = file(fname)
        buf = fin.read()
        fin.close()
        for key in self:
            re_key = re.compile('^%s="[^"]+"$' % key, re.M)
            mobj = re_key.search(buf)
            if mobj is None:
                start = len(buf)
                end = len(buf)
            else:
                start = mobj.start(0)
                end = mobj.end(0) + 1
            print start, end
            buf = buf[:start] + '%s="%s"\n' % (key, self[key]) + buf[end:]
        tmpname = '%s.%d-tmp' % (fname, os.getpid())
        ftmp = file(tmpname, 'w')
        try:
            ftmp.write(buf)
            ftmp.close()
            os.rename(tmpname, fname)
        except (IOError, OSError):
            # Never leave behind tempfiles
            os.unlink(tmpname)
            raise
