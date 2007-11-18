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
        cls.c_iptables = None

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
        if self.c_iptables is None:
            try:
                self.execute_as_root('iptables -L -n')
                self.execute_as_root('conntrack -L')
            except RuntimeError:
                self.c_iptables = False
            else:
                self.c_iptables = True
        return self.c_iptables

    def remove_network_blocks(self):
        if not self.root_tests_allowed() or not \
                self.firewall_tests_allowed():
            raise RuntimeError, 'Action not allowed by configuration.'
        if not self.iptables_supported():
            raise RuntimeError, 'Iptables not supported on this system.'
        self.execute_as_root('iptables -t nat -F')
        self.execute_as_root('conntrack -F')

    def block_outgoing_traffic(self, protocol, port):
        """Block outgoing traffic of type `protocol' with destination `port'."""
        # Unfortunately we cannot simply insert a rule like this: -A OUTPUT -m
        # udp -p udp--dport 389 -j DROP.  If we do this the kernel code will
        # be smart and return an error when sending trying to connect or send
        # a datagram. In order realistically emulate a network failure we
        # instead redirect packets the discard port on localhost. This
        # complicates stopping the emulated failure though: merely flushling
        # the nat table is not enough. We also need to flush the conntrack
        # table that keeps state for NAT'ed connections even after the rule
        # that caused the NAT in the first place has been removed.
        self.execute_as_root('iptables -t nat -A OUTPUT -m %s -p %s --dport %d'
                             ' -j DNAT --to-destination 127.0.0.1:9' %
                             (protocol, protocol, port))
