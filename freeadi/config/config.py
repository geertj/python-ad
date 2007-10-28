#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import os


class Config(dict):
    """Base class for configuration files."""

    def __init__(self, parser, writer):
        """Constructor. Requires a parser and a writer implementing the
        configuration file syntax."""
        self.parser = parser
        self.writer = writer

    def read(self, fname):
        """Read configuration data from the file `fname'."""
        fin = file(fname)
        try:
            parser = self.parser()
            result = parser.parse(fin)
        finally:
            fin.close()
        self.clear()
        self.update(result)

    def write(self, fname):
        """Write configuration data to the file `fname'.

        This function writes the output to a temporary file and then
        atomically renames that in place."""
        tmpname = '%s.%d-tmp' % (fname, os.getpid())
        fout = file(tmpname, 'w')
        try:
            try:
                writer = self.writer()
                writer.write(self, fout)
                os.rename(tmpname, fname)
            except:
                os.unlink(tmpname)
                raise
        finally:
            fout.close()
