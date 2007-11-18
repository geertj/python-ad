#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import os
import os.path
import sys
import tempfile
import pexpect
import logging

from ConfigParser import ConfigParser


class BaseTest(object):
    """Base class for FreeADI tests."""

    def setup_class(cls):
        config = ConfigParser()
        fname = os.environ['FREEADI_TEST_CONFIG']
        config.read(fname)
        cls.c_config = config
        cls.c_basedir = os.path.dirname(fname)
        logger = logging.getLogger('freeadi')
        handler = logging.StreamHandler()
        format = '%(levelname)s [%(name)s] %(message)s'
        formatter = logging.Formatter(format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    def setup_method(cls, method):
        cls.c_tempfiles = []

    def teardown_method(cls, method):
        for fname in cls.c_tempfiles:
            try:
                os.unlink(fname)
            except OSError:
                pass
        cls.c_tempfiles = []

    def config(self):
        return self.c_config

    def _dedent(self, s):
        lines = s.splitlines()
        for i in range(len(lines)):
            lines[i] = lines[i].lstrip()
        if lines and not lines[0]:
            lines = lines[1:]
        if lines and not lines[-1]:
            lines = lines[:-1]
        return '\n'.join(lines) + '\n'

    def tempfile(self, contents=None):
        fd, name = tempfile.mkstemp()
        if contents:
            os.write(fd, self._dedent(contents))
        os.close(fd)
        self.c_tempfiles.append(name)
        return name

    def basedir(self):
        return self.c_basedir

    def administrator_tests_allowed(self):
        config = self.config()
        return config.getboolean('test', 'administrator_tests')

    def domain(self):
        if not self.online_tests_allowed():
            raise RuntimeError, 'Online tests not allowed by configuration.'
        config = self.config()
        domain = config.get('test', 'domain')
        if domain is None:
            raise RuntimeError, 'Test configuration variable `domain\' not set.'
        return domain

    def admin_account(self):
        if not self.online_tests_allowed():
            raise RuntimeError, 'Online tests not allowed by configuration.'
        config = self.config()
        account = config.get('test', 'admin_account')
        if account is None:
            raise RuntimeError, 'Test configuration variable `admin_account\' not set.'
        return account

    def admin_password(self):
        if not self.online_tests_allowed():
            raise RuntimeError, 'Online tests not allowed by configuration.'
        config = self.config()
        password = config.get('test', 'admin_password')
        if password is None:
            raise RuntimeError, 'Test configuration variable `admin_password\' not set.'
        return password

    def online_tests_allowed(self):
        config = self.config()
        return config.getboolean('test', 'online_tests')

    def root_tests_allowed(self):
        config = self.config()
        return config.getboolean('test', 'root_tests')

    def root_account(self):
        if not self.root_tests_allowed():
            raise RuntimeError, 'Root tests are not allowed by configuration.'
        config = self.config()
        account = config.get('test', 'root_account')
        if account is None:
            raise RuntimeError, 'Test configuration variable `root_account\' not set.'
        return account

    def root_password(self):
        if not self.root_tests_allowed():
            raise RuntimeError, 'Root tests are not allowed by configuration.'
        config = self.config()
        password = config.get('test', 'root_password')
        if password is None:
            raise RuntimeError, 'Test configuration variable `root_password\' not set.'
        return password

    def execute_as_root(self, command):
        if not self.root_tests_allowed():
            raise RuntimeError, 'Root tests are not allowed by configuration.'
        child = pexpect.spawn('su -c "%s" %s' % (command, self.root_account()))
        child.expect('.*:')
        child.sendline(self.root_password())
        child.expect(pexpect.EOF)
        assert not child.isalive()
        if child.exitstatus != 0:
            m = 'Root command exited with status %s' % child.exitstatus
            raise RuntimeError, m
        return child.before

    def firewall_tests_allowed(self):
        config = self.config()
        return config.getboolean('test', 'firewall_tests')

    def iptables_supported(self):
        try:
            output = self.execute_as_root('iptables -L -n')
        except RuntimeError:
            return False
        try:
            output = self.execute_as_root('conntrack -L')
        except RuntimeError:
            return False
        return True
