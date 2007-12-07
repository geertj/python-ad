#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

import os
import time
import tempfile

from ad.core.object import factory
from ad.core.exception import Error
from ad.core.locate import Locator
from ad.core.locate import KERBEROS_PORT, KPASSWD_PORT
from ad.protocol import krb5


class Creds(object):
    """AD credential management."""

    c_config_stack = {}
    c_ccache_stack = {}

    def __init__(self, domain, use_system_config=False):
        """Constructor.

        The `domain' parameter specifies the default domain. The default
        domain is used when a principal is specified without a domain in the
        .acquire() method.
        """
        self.m_domain = domain.upper()
        self.m_domains = {}
        self.m_principal = None
        self.m_ccache = None
        self.m_config = None
        self.m_use_system_config = use_system_config
        self.m_config_cleanup = []

    def __del__(self):
        """Destructor. This releases all currently held credentials and cleans
        up temporary files."""
        self.release()

    def load(self):
        """Load credentials from the OS."""
        ccache = krb5.cc_default()
        if not os.access(ccache, os.R_OK):
            raise Error, 'No ccache found'
        self.m_principal = krb5.cc_get_principal(ccache)
        self._init_ccache()
        krb5.cc_copy_creds(ccache, self.m_ccache)
        self._activate_ccache()
        self._resolve_servers_for_domain(self.m_domain)

    def acquire(self, principal, password=None, keytab=None, server=None):
        """Acquire credentials for `principal'.

        The `principal' argument specifies the principal for which to acquire
        credentials. If it is not a qualified pricipal in the form of
        principal@domain, then the default domain is assumed.

        If `password' is given, it is the password to the principal.
        Otherwise, `keytab' specifies the keytab to use. The `keytab' argument
        can either specify the absolute path name of a file, or can be None
        (the default) which uses the system-specific default keytab.
        """
        if '@' in principal:
            principal, domain = principal.split('@')
            domain = domain.upper()
        else:
            domain = self.m_domain
        principal = '%s@%s' % (principal, domain)
        self._init_ccache()
        self._activate_ccache()
        if not self.m_use_system_config:
            if server is None:
                self._resolve_servers_for_domain(domain)
            else:
                self._set_servers_for_domain(domain, [server])
        try:
            if password is not None:
                krb5.get_init_creds_password(principal, password)
            else:
                krb5.get_init_creds_keytab(principal, keytab)
        except krb5.Error, err:
            raise Error, str(err)
        self.m_principal = principal

    def release(self):
        """Release all credentials."""
        self._release_ccache()
        self._release_config()
        self.m_principal = None

    def principal(self):
        """Return the current principal."""
        return self.m_principal

    def _ccache_name(self):
        """Return the Kerberos credential cache file name."""
        return self.m_ccache

    def _config_name(self):
        """Return the Kerberos config file name."""
        return self.m_config

    def _init_ccache(self):
        """Initialize Kerberos ccache."""
        if self.m_ccache:
            return
        fd, fname = tempfile.mkstemp()
        os.close(fd)
        self.m_ccache = fname

    def _activate_ccache(self):
        """Active our private credential cache."""
        assert self.m_ccache is not None
        orig = self._environ('KRB5CCNAME')
        if orig != self.m_ccache:
            self._set_environ('KRB5CCNAME', self.m_ccache)
            self.c_ccache_stack[self.m_ccache] = (True, orig)

    def _release_ccache(self):
        """Release the current Kerberos configuration."""
        if not self.m_ccache:
            return
        # Things are complicated by the fact that multiple instances of this
        # class my exist. Therefore we need to keep track whether we have set
        # the current $KRB5CCNAME or someone else. If it is ourselves we are
        # fine, but if not we need to mark that the class who replaced our
        # value should not point back to us when that class releases its
        # credentials because we are releasing those credentials now.
        assert self.m_ccache in self.c_ccache_stack
        active, orig = self.c_ccache_stack[self.m_ccache]
        assert active
        ccache = self._environ('KRB5CCNAME')
        if ccache == self.m_ccache:
            while True:
                active, orig = self.c_ccache_stack[ccache]
                del self.c_ccache_stack[ccache]
                if orig not in self.c_ccache_stack or \
                        self.c_ccache_stack[orig][0]:
                    self._set_environ('KRB5CCNAME', orig)
                    break
                ccache = orig
        else:
            self.c_ccache_stack[self.m_ccache] = (False, orig)
        try:
            os.remove(self.m_ccache)
        except OSError:
            pass
        self.m_ccache = None

    def _resolve_servers_for_domain(self, domain, force=False):
        """Resolve domain controllers for a domain."""
        if self.m_use_system_config:
            return
        if domain in self.m_domains and not force:
            return
        locator = factory(Locator)
        result = locator.locate_many(domain)
        self.m_domains[domain] = list(result)
        # Re-init every time
        self._init_config()
        self._write_config()
        self._activate_config()

    def _set_servers_for_domain(self, domain, servers):
        """Set the servers to use for `domain'."""
        if self.m_use_system_config:
            return
        self.m_domains[domain] = servers
        self._init_config()
        self._write_config()
        self._activate_config()

    def _init_config(self):
        """Initialize Kerberos config."""
        if self.m_config and self.m_config in self.c_config_stack:
            # Delete current config and create one under a new file name. This
            # seems to be required by the Kerberos libraries that do not
            # reload the configuration file otherwise.
            active, orig = self.c_config_stack[self.m_config]
            self.c_config_stack[self.m_config] = (False, orig)
            # unlink this config file on activate of new config
            self.m_config_cleanup.append(self.m_config)
        fd, fname = tempfile.mkstemp()
        os.close(fd)
        self.m_config = fname

    def _write_config(self):
        """Write the Kerberos configuration file."""
        assert self.m_config is not None
        ftmp = '%s.%d-tmp' % (self.m_config, os.getpid())
        fout = file(ftmp, 'w')
        try:
            fout.write('# krb5.conf generated by Python-AD at %s\n' %
                       time.asctime())
            fout.write('[libdefaults]\n')
            fout.write('  default_realm = %s\n' % self.m_domain)
            fout.write('  dns_lookup_kdc = false\n')
            fout.write('  default_tgs_enctypes = rc4-hmac\n')
            fout.write('  default_tkt_enctypes = rc4-hmac\n')
            fout.write('[realms]\n')
            for domain in self.m_domains:
                fout.write('  %s = {\n' % domain)
                for server in self.m_domains[domain]:
                    fout.write('    kdc = %s:%d\n' % (server, KERBEROS_PORT))
                    fout.write('    kpasswd_server = %s:%d\n'
                               % (server, KPASSWD_PORT))
                fout.write('  }\n')
            fout.close()
            os.rename(ftmp, self.m_config)
        finally:
            try:
                os.remove(ftmp)
            except OSError:
                pass

    def _activate_config(self):
        """Activate the Kerberos config."""
        if self.m_use_system_config:
            return
        assert self.m_config is not None
        orig = self._environ('KRB5_CONFIG')
        if orig != self.m_config:
            self._set_environ('KRB5_CONFIG', self.m_config)
            self.c_config_stack[self.m_config] = (True, orig)
        for fname in self.m_config_cleanup:
            try:
                os.remove(fname)
            except OSError:
                pass
        self.m_config_cleanup = []

    def _release_config(self):
        """Release the current Kerberos configuration."""
        if self.m_use_system_config or not self.m_config:
            return
        # See the comments with _release_ccache().
        assert self.m_config in self.c_config_stack
        active, orig = self.c_config_stack[self.m_config]
        assert active
        config = self._environ('KRB5_CONFIG')
        if config == self.m_config:
            while True:
                active, orig = self.c_config_stack[config]
                del self.c_config_stack[config]
                if orig not in self.c_config_stack or \
                        self.c_config_stack[orig][0]:
                    self._set_environ('KRB5_CONFIG', orig)
                    break
                config = orig
        else:
            self.c_config_stack[self.m_config] = (False, orig)
        try:
            os.remove(self.m_config)
        except OSError:
            pass
        self.m_config = None

    def _environ(self, name):
        """Return an environment variable or None in case it doesn't exist."""
        return os.environ.get(name)

    def _set_environ(self, name, value):
        """Set or delete an environment variable."""
        if value is None:
            try:
                del os.environ[name]
            except KeyError:
                pass
        else:
            os.environ[name] = value
