#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.config.ldap import LdapConfig
from freeadi.config.test.support import ConfigTest


class TestLdap(ConfigTest):
    """Test suite for LdapConfig."""

    def test_simple(self):
        conf = """
            key_one value1
            key_two value2
            key_two value3
            """
        fname = self.make_file(conf)
        config = LdapConfig()
        config.read(fname)
        fname = self.tempfile()
        config.write(fname)
        config2 = LdapConfig()
        config2.read(fname)
        assert dict(config) == dict(config2)

    def test_multi_read(self):
        conf1 = """
            key_one value1
            """
        fn1 = self.make_file(conf1)
        conf2 = """
            key_two value2
            """
        fn2 = self.make_file(conf2)
        config = LdapConfig()
        config.read(fn1)
        assert 'key_one' in config
        assert config['key_one'] == 'value1'
        assert 'key_two' not in config
        config.read(fn2)
        assert 'key_two' in config
        assert config['key_two'] == 'value2'
        assert 'key_one' not in config
