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
import py.test

from ConfigParser import ConfigParser


class Error(Exception):
    """Test error."""


class BaseTest(object):
    """Base class for FreeADI tests."""

    def setup_class(cls):
        config = ConfigParser()
        fname = os.environ.get('FREEADI_TEST_CONFIG')
        if fname is None:
            raise Error, 'FreeADI test configuration file not specified.'
        if not os.access(fname, os.R_OK):
            raise Error, 'FreeADI test configuration file does not exist.'
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

    def tempfile(self, contents=None, remove=False):
        fd, name = tempfile.mkstemp()
        if contents:
            os.write(fd, self._dedent(contents))
        elif remove:
            os.remove(name)
        os.close(fd)
        self.c_tempfiles.append(name)
        return name

    def basedir(self):
        return self.c_basedir

    def require(self, ad=False, root=False, firewall=False, admin=False,
                ad_write=False):
        config = self.config()
        if ad and not config.getboolean('test', 'ad_tests'):
            py.test.skip('test disabled by configuration')
            if not config.get('test', 'domain'):
                py.test.skip('ad tests enabled but no domain given')
        if root:
            if not config.getboolean('test', 'root_tests'):
                py.test.skip('test disabled by configuration')
            if not config.get('test', 'root_account') or \
                    not config.get('test', 'root_password'):
                py.test.skip('root tests enabled but no username/pw given')
        if firewall:
            if not config.getboolean('test', 'firewall_tests'):
                py.test.skip('test disabled by configuration')
            if not self._iptables_supported():
                py.test.skip('iptables/conntrack not available')
        if admin:
            if not config.getboolean('test', 'admin_tests'):
                py.test.skip('test disabled by configuration')
            if not config.get('test', 'admin_account') or \
                    not config.get('test', 'admin_password'):
                py.test.skip('admin tests enabled but no username/pw given')
        if ad_write and not config.getboolean('test', 'ad_write_tests'):
            py.test.skip('test disabled by configuration')

    def domain(self):
        self.require(ad=True)
        config = self.config()
        domain = config.get('test', 'domain')
        return domain

    def root_account(self):
        self.require(root=True)
        config = self.config()
        account = config.get('test', 'root_account')
        return account

    def root_password(self):
        self.require(root=True)
        config = self.config()
        password = config.get('test', 'root_password')
        return password

    def admin_account(self):
        self.require(admin=True)
        config = self.config()
        account = config.get('test', 'admin_account')
        return account

    def admin_password(self):
        self.require(admin=True)
        config = self.config()
        password = config.get('test', 'admin_password')
        return password

    def execute_as_root(self, command):
        self.require(root=True)
        child = pexpect.spawn('su -c "%s" %s' % (command, self.root_account()))
        child.expect('.*:')
        child.sendline(self.root_password())
        child.expect(pexpect.EOF)
        assert not child.isalive()
        if child.exitstatus != 0:
            m = 'Root command exited with status %s' % child.exitstatus
            raise Error, m
        return child.before

    def _iptables_supported(self):
        if self.c_iptables is None:
            try:
                self.execute_as_root('iptables -L -n')
                self.execute_as_root('conntrack -L')
            except Error:
                self.c_iptables = False
            else:
                self.c_iptables = True
        return self.c_iptables

    def remove_network_blocks(self):
        self.require(root=True, firewall=True)
        self.execute_as_root('iptables -t nat -F')
        self.execute_as_root('conntrack -F')

    def block_outgoing_traffic(self, protocol, port):
        """Block outgoing traffic of type `protocol' with destination `port'."""
        self.require(root=True, firewall=True)
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
