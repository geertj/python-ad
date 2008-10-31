#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

import os
import os.path
import sys
import tempfile
import pexpect
import logging

from nose import SkipTest
from ConfigParser import ConfigParser


class Error(Exception):
    """Test error."""


class BaseTest(object):
    """Base class for Python-AD tests."""

    @classmethod
    def setup_class(cls):
        config = ConfigParser()
        fname = os.environ.get('FREEADI_TEST_CONFIG')
        if fname is None:
            raise Error, 'Python-AD test configuration file not specified.'
        if not os.access(fname, os.R_OK):
            raise Error, 'Python-AD test configuration file does not exist.'
        config.read(fname)
        cls.c_config = config
        cls.c_basedir = os.path.dirname(fname)
        logger = logging.getLogger('ad')
        handler = logging.StreamHandler(sys.stdout)
        format = '%(levelname)s [%(name)s] %(message)s'
        formatter = logging.Formatter(format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        cls.c_iptables = None
        cls.c_tempfiles = []

    @classmethod
    def teardown_class(cls):
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

    def require(self, ad_user=False, local_admin=False, ad_admin=False,
                firewall=False, expensive=False):
        if firewall:
            local_admin = True
        config = self.config()
        if ad_user and not config.getboolean('test', 'readonly_ad_tests'):
            raise SkipTest, 'test disabled by configuration'
            if not config.get('test', 'domain'):
                raise SkipTest, 'ad tests enabled but no domain given'
            if not config.get('test', 'ad_user_account') or \
                    not config.get('test', 'ad_user_password'):
                raise SkipTest, 'readonly ad tests enabled but no user/pw given'
        if local_admin:
            if not config.getboolean('test', 'intrusive_local_tests'):
                raise SkipTest, 'test disabled by configuration'
            if not config.get('test', 'local_admin_account') or \
                    not config.get('test', 'local_admin_password'):
                raise SkipTest, 'intrusive local tests enabled but no user/pw given'
        if ad_admin:
            if not config.getboolean('test', 'intrusive_ad_tests'):
                raise SkipTest, 'test disabled by configuration'
            if not config.get('test', 'ad_admin_account') or \
                    not config.get('test', 'ad_admin_password'):
                raise SkipTest, 'intrusive ad tests enabled but no user/pw given'
        if firewall and not self._iptables_supported():
            raise SkipTest, 'iptables/conntrack not available'
        if expensive and not config.getboolean('test', 'expensive_tests'):
            raise SkipTest, 'test disabled by configuration'

    def domain(self):
        config = self.config()
        domain = config.get('test', 'domain')
        return domain

    def ad_user_account(self):
        self.require(ad_user=True)
        account = self.config().get('test', 'ad_user_account')
        return account

    def ad_user_password(self):
        self.require(ad_user=True)
        password = self.config().get('test', 'ad_user_password')
        return password

    def local_admin_account(self):
        self.require(local_admin=True)
        account = self.config().get('test', 'local_admin_account')
        return account

    def local_admin_password(self):
        self.require(local_admin=True)
        password = self.config().get('test', 'local_admin_password')
        return password

    def ad_admin_account(self):
        self.require(ad_admin=True)
        account = self.config().get('test', 'ad_admin_account')
        return account

    def ad_admin_password(self):
        self.require(ad_admin=True)
        password = self.config().get('test', 'ad_admin_password')
        return password

    def execute_as_root(self, command):
        self.require(local_admin=True)
        child = pexpect.spawn('su -c "%s" %s' % \
                              (command, self.local_admin_account()))
        child.expect('.*:')
        child.sendline(self.local_admin_password())
        child.expect(pexpect.EOF)
        assert not child.isalive()
        if child.exitstatus != 0:
            m = 'Root command exited with status %s' % child.exitstatus
            raise Error, m
        return child.before

    def acquire_credentials(self, principal, password, ccache=None):
        if ccache is None:
            ccache = ''
        else:
            ccache = '-c %s' % ccache
        child = pexpect.spawn('kinit %s %s' % (principal, ccache))
        child.expect(':')
        child.sendline(password)
        child.expect(pexpect.EOF)
        assert not child.isalive()
        if child.exitstatus != 0:
            m = 'Command kinit exited with status %s' % child.exitstatus
            raise Error, m

    def list_credentials(self, ccache=None):
        if ccache is None:
            ccache = ''
        child = pexpect.spawn('klist %s' % ccache)
        try:
            child.expect('Ticket cache: ([a-zA-Z0-9_/.:-]+)\r\n')
        except pexpect.EOF:
            m = 'Command klist exited with status %s' % child.exitstatus
            raise Error, m
        ccache = child.match.group(1)
        child.expect('Default principal: ([a-zA-Z0-9_/.:@-]+)\r\n')
        principal = child.match.group(1)
        creds = []
        while True:
            i = child.expect(['\r\n', pexpect.EOF,
                              '\d\d/\d\d/\d\d \d\d:\d\d:\d\d\s+' \
                              '\d\d/\d\d/\d\d \d\d:\d\d:\d\d\s+' \
                              '([a-zA-Z0-9_/.:@-]+)\r\n'])
            if i == 0:
                continue
            elif i == 1:
                break
            creds.append(child.match.group(1))
        return ccache, principal, creds

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
        self.require(local_admin=True, firewall=True)
        self.execute_as_root('iptables -t nat -F')
        self.execute_as_root('conntrack -F')

    def block_outgoing_traffic(self, protocol, port):
        """Block outgoing traffic of type `protocol' with destination `port'."""
        self.require(local_admin=True, firewall=True)
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
