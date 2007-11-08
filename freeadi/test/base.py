#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import os
import sys
import tempfile
import pexpect

from ConfigParser import ConfigParser


class BaseTest(object):
    """Base class for FreeADI tests."""

    def setup_class(cls):
        config = ConfigParser()
        fname = os.environ['FREEADI_TEST_CONFIG']
        config.read(fname)
        cls.c_config = config

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

    def online(self):
        config = self.config()
        return config.getboolean('test', 'online_tests')

    def domain(self):
        config = self.config()
        domain = config.get('test', 'domain')
        if domain is None:
            raise ValueError, 'Test configuration variable `domain\' not set.'
        return domain

    def admin_account(self):
        config = self.config()
        account = config.get('test', 'admin_account')
        if account is None:
            raise ValueError, 'Test configuration variable `admin_account\' not set.'
        return account

    def admin_password(self):
        config = self.config()
        password = config.get('test', 'admin_password')
        if password is None:
            raise ValueError, 'Test configuration variable `admin_password\' not set.'
        return password

    def acquire_credentials(self, domain, principal, password):
        template = """
            [libdefaults]
            default_realm = %s
            default_tgs_enctypes = rc4-hmac
            default_tkt_enctypes = rc4-hmac
            dns_lookup_kdc = true
            """
        krb5conf = self.tempfile(template % domain.upper())
        os.environ['KRB5_CONFIG'] = krb5conf
        krb5ccname = self.tempfile()
        os.environ['KRB5CCNAME'] = krb5ccname
        kinit = pexpect.spawn('kinit %s' % principal)
        kinit.expect('.*:')
        kinit.sendline(password)
        kinit.expect(pexpect.EOF)

    def acquire_admin_credentials(self):
        config = self.config()
        domain = config.get('test', 'domain')
        admin = config.get('test', 'admin_account')
        passwd = config.get('test', 'admin_password')
        self.acquire_credentials(domain, admin, passwd)
