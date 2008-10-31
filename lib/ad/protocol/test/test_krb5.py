#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

import os
import stat
import pexpect

from nose.tools import assert_raises
from ad.protocol import krb5
from ad.test.base import BaseTest, Error


class TestKrb5(BaseTest):
    """Test suite for protocol.krb5."""

    def test_cc_default(self):
        self.require(ad_user=True)
        domain = self.domain().upper()
        principal = '%s@%s' % (self.ad_user_account(), domain)
        password = self.ad_user_password()
        self.acquire_credentials(principal, password)
        ccache = krb5.cc_default()
        ccname, princ, creds = self.list_credentials(ccache)
        assert princ.lower() == principal.lower()
        assert len(creds) > 0
        assert creds[0] == 'krbtgt/%s@%s' % (domain, domain)

    def test_cc_copy_creds(self):
        self.require(ad_user=True)
        domain = self.domain().upper()
        principal = '%s@%s' % (self.ad_user_account(), domain)
        password = self.ad_user_password()
        self.acquire_credentials(principal, password)
        ccache = krb5.cc_default()
        cctmp = self.tempfile()
        assert_raises(Error, self.list_credentials, cctmp)
        krb5.cc_copy_creds(ccache, cctmp)
        ccname, princ, creds = self.list_credentials(cctmp)
        assert princ.lower() == principal.lower()
        assert len(creds) > 0
        assert creds[0] == 'krbtgt/%s@%s' % (domain, domain)

    def test_cc_get_principal(self):
        self.require(ad_user=True)
        domain = self.domain().upper()
        principal = '%s@%s' % (self.ad_user_account(), domain)
        password = self.ad_user_password()
        self.acquire_credentials(principal, password)
        ccache = krb5.cc_default()
        princ = krb5.cc_get_principal(ccache)
        assert princ.lower() == principal.lower()
