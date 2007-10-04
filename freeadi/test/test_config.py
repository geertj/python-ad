#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

import os
import py.test
import tempfile
from freeadi import FreeADIError
from freeadi.config import FreeADIConfig


class TestFreeADIConfig(object):
    """Test suite for freeadi.config."""

    def test_singleton(self):
        FreeADIConfig._fname = os.getenv('TESTCONF')
        inst = FreeADIConfig.get()
        inst2 = FreeADIConfig.get()
        assert inst is inst2

    def tempfile(self):
        fd, name = tempfile.mkstemp()
        os.close(fd)
        return name

    def write_file(self, fname, s):
        fout = file(fname, 'w')
        lines = s.splitlines()
        for line in lines:
            fout.write(line.lstrip() + '\n')
        fout.close()

    def test_syntax(self):
        fname = self.tempfile()
        good = """
            # test syntax file
            VAR="value"
            """
        self.write_file(fname, good)
        cfg = FreeADIConfig()
        cfg.read(fname)
        bad1 = """
            # test syntax file
            VAR="value
        """
        self.write_file(fname, bad1)
        cfg = FreeADIConfig()
        py.test.raises(FreeADIError, cfg.read, fname)
        bad2 = """
            VAR = "value"
            """
        self.write_file(fname, bad2)
        cfg = FreeADIConfig()
        py.test.raises(FreeADIError, cfg.read, fname)
        bad3 = """
            VAR=value
            """
        self.write_file(fname, bad3)
        cfg = FreeADIConfig()
        py.test.raises(FreeADIError, cfg.read, fname)
        bad4 = """
            test
            """
        self.write_file(fname, bad4)
        cfg = FreeADIConfig()
        py.test.raises(FreeADIError, cfg.read, fname)

    def test_read(self):
        fname = self.tempfile()
        buf = """
            VAR1="value"
            VAR2="value2"
            VAR3="Value With Spaces"
            VAR4="value4"
            VAR4="value5"
            """
        self.write_file(fname, buf)
        cfg = FreeADIConfig()
        cfg.read(fname)
        assert cfg['VAR1'] == 'value'
        assert cfg['VAR2'] == 'value2'
        assert cfg['VAR3'] == 'Value With Spaces'
        assert cfg['VAR4'] == 'value5'
        assert 'VAR5' not in cfg

    def test_write(self):
        fname = self.tempfile()
        buf = """
            # comment 1
            VAR1="value1"
            # comment 2
            VAR2="value2"
            """
        self.write_file(fname, buf)
        cfg = FreeADIConfig()
        cfg.read(fname)
        cfg['VAR1'] = 'value3'
        cfg['VAR3'] = 'value4'
        cfg.write(fname)
        buf = file(fname).read()
        assert buf == '\n# comment 1\nVAR1="value3"\n# comment 2\n' + \
                      'VAR2="value2"\n\nVAR3="value4"\n'
