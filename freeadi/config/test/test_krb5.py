#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.config.krb5 import Krb5Config
from freeadi.config.test.support import ConfigTest


class TestKrb5(ConfigTest):
    """Test suite for Krb5Config."""

    def test_simple(self):
        conf = """
            [section1]
            key1 = value1
            """
        fname = self.make_file(conf)
        config = Krb5Config()
        config.read(fname)
        fname = self.tempfile()
        config.write(fname)
        config2 = Krb5Config()
        config2.read(fname)
        assert dict(config) == dict(config2)

    def test_multi_read(self):
        conf1 = """
            [section1]
            key1 = value1
            """
        fn1 = self.make_file(conf1)
        conf2 = """
            [section1]
            key2 = value2
            """
        fn2 = self.make_file(conf2)
        config = Krb5Config()
        config.read(fn1)
        assert 'section1' in config
        assert 'key1' in config['section1']
        assert config['section1']['key1'] == 'value1'
        assert 'key2' not in config['section1']
        config.read(fn2)
        assert 'section1' in config
        assert 'key2' in config['section1']
        assert config['section1']['key2'] == 'value2'
        assert 'key1' not in config['section1']
