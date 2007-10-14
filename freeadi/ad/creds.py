#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

import os
import tempfile

from freeadi.ad import krb5


class Creds(object):
    """Credentials for working with AD."""

    def __init__(self):
        """Constructor"""
        self.m_tempfiles = []
        self.m_environment = {}
        self.m_krb5_config_installed = False
        self.m_krb5_ccache_installed = False

    def _install_krb5_config(self):
        """Create a generic krb5 config file in a temporary file."""
        if self.m_krb5_config_installed:
            return
        template = """
            [libdefaults]
            default_tgs_enctypes = rc4-hmac
            default_tkt_enctypes = rc4-hmac
            dns_lookup_kdc = true
            """
        name, fd = tempfile.mkstemp()
        os.write(fd, template % domain.upper())
        os.close(fd)
        self.m_environment['KRB5_CONFIG'] = os.environ.get('KRB5_CONFIG')
        self.m_tempfiles.append(name)
        os.environ['KRB5_CONFIG'] = name
        self.m_krb5_config_installed = True

    def _install_ccache(self):
        """Create a fresh credentials cache in a temporary file."""
        if self.m_krb5_ccache_installed:
            return
        name, fd = tempfile.mkstemp()
        os.close(fd)
        self.m_environment['KRB5CCNAME'] = os.environ.get('KRB5CCNAME')
        self.m_tempfiles.append(name)
        os.environ['KRB5CCNAME'] = name
        self.m_krb5_ccache_installed = True

    def acquire(self, domain, principal, password):
        """Acquire credentials for user `principal' in `domain' using the
        password `password'.
        """
        self._install_krb5_config()
        self._install_credentials_cache()
        principal = '%s@%s' % (principal, domain.upper())
        krb5.get_init_creds_password(principal, password)

    def acquire_keytab(self, domain, principal):
        """Acquire credentials for user `principal' in `domain' using the
        system keytab."""
        self._install_krb5_config()
        self._install_credentials_cache()
        principal = '%s@%s' % (principal, domain.upper())
        krb5.get_init_creds_keytab(principal, password)

    def release(self):
        """Release credentials.

        Note this function must be called or otherwise temporary files may
        linger around on the system.
        """
        for name in self.m_tempfiles:
            try:
                os.unlink(name)
            except OSError:
                pass
        for key,value in self.m_environment:
            if value is None:
                try:
                    del os.environ[key]
                except KeyError:
                    pass
            else:
                os.environ[key] = value
