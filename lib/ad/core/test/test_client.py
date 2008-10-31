#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

from nose.tools import assert_raises

from ad.test.base import BaseTest
from ad.core.object import activate
from ad.core.client import Client
from ad.core.locate import Locator
from ad.core.constant import *
from ad.core.creds import Creds
from ad.core.exception import Error as ADError, LDAPError


class TestADClient(BaseTest):
    """Test suite for ADClient"""

    def test_search(self):
        self.require(ad_user=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_user_account(), self.ad_user_password())
        activate(creds)
        client = Client(domain)
        result = client.search('(objectClass=user)')
        assert len(result) > 1

    def _delete_user(self, client, name, server=None):
        # Delete any user that may conflict with a newly to be created user
        filter = '(|(cn=%s)(sAMAccountName=%s)(userPrincipalName=%s))' % \
                 (name, name, '%s@%s' % (name, client.domain().upper()))
        result = client.search('(&(objectClass=user)(sAMAccountName=%s))' % name,
                               server=server)
        for res in result:
            client.delete(res[0], server=server)

    def _create_user(self, client, name, server=None):
        attrs = []
        attrs.append(('cn', [name]))
        attrs.append(('sAMAccountName', [name]))
        attrs.append(('userPrincipalName', ['%s@%s' % (name, client.domain().upper())]))
        ctrl = AD_USERCTRL_ACCOUNT_DISABLED | AD_USERCTRL_NORMAL_ACCOUNT
        attrs.append(('userAccountControl', [str(ctrl)]))
        attrs.append(('objectClass', ['user']))
        dn = 'cn=%s,cn=users,%s' % (name, client.dn_from_domain_name(client.domain()))
        self._delete_user(client, name, server=server)
        client.add(dn, attrs, server=server)
        return dn

    def _delete_obj(self, client, dn, server=None):
        try:
            client.delete(dn, server=server)
        except (ADError, LDAPError):
            pass

    def _create_ou(self, client, name, server=None):
        attrs = []
        attrs.append(('objectClass', ['organizationalUnit']))
        attrs.append(('ou', [name]))
        dn = 'ou=%s,%s' % (name, client.dn_from_domain_name(client.domain()))
        self._delete_obj(client, dn, server=server)
        client.add(dn, attrs, server=server)
        return dn

    def test_add(self):
        self.require(ad_admin=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        user = self._create_user(client, 'test-usr')
        self._delete_obj(client, user)

    def test_delete(self):
        self.require(ad_admin=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        dn = self._create_user(client, 'test-usr')
        client.delete(dn)

    def test_modify(self):
        self.require(ad_admin=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        user = self._create_user(client, 'test-usr')
        mods = []
        mods.append(('replace', 'sAMAccountName', ['test-usr-2']))
        client.modify(user, mods)
        self._delete_obj(client, user)

    def test_modrdn(self):
        self.require(ad_admin=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        result = client.search('(&(objectClass=user)(sAMAccountName=test-usr))')
        if result:
            client.delete(result[0][0])
        user = self._create_user(client, 'test-usr')
        client.modrdn(user, 'cn=test-usr2')
        result = client.search('(&(objectClass=user)(cn=test-usr2))')
        assert len(result) == 1

    def test_rename(self):
        self.require(ad_admin=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        result = client.search('(&(objectClass=user)(sAMAccountName=test-usr))')
        if result:
            client.delete(result[0][0])
        user = self._create_user(client, 'test-usr')
        client.rename(user, 'cn=test-usr2')
        result = client.search('(&(objectClass=user)(cn=test-usr2))')
        assert len(result) == 1
        user = result[0][0]
        ou = self._create_ou(client, 'test-ou')
        client.rename(user, 'cn=test-usr', ou)
        newdn = 'cn=test-usr,%s' % ou
        result = client.search('(&(objectClass=user)(cn=test-usr))')
        assert len(result) == 1
        assert result[0][0].lower() == newdn.lower()

    def test_forest(self):
        self.require(ad_user=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_user_account(), self.ad_user_password())
        activate(creds)
        client = Client(domain)
        forest = client.forest()
        assert forest
        assert forest.isupper()

    def test_domains(self):
        self.require(ad_user=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_user_account(), self.ad_user_password())
        activate(creds)
        client = Client(domain)
        domains = client.domains()
        for domain in domains:
            assert domain
            assert domain.isupper()

    def test_naming_contexts(self):
        self.require(ad_user=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_user_account(), self.ad_user_password())
        activate(creds)
        client = Client(domain)
        naming_contexts = client.naming_contexts()
        assert len(naming_contexts) >= 3

    def test_search_all_domains(self):
        self.require(ad_user=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_user_account(), self.ad_user_password())
        activate(creds)
        client = Client(domain)
        domains = client.domains()
        for domain in domains:
            base = client.dn_from_domain_name(domain)
            result = client.search('(objectClass=*)', base=base, scope='base')
            assert len(result) == 1

    def test_search_schema(self):
        self.require(ad_user=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_user_account(), self.ad_user_password())
        activate(creds)
        client = Client(domain)
        base = client.schema_base()
        result = client.search('(objectClass=*)', base=base, scope='base')
        assert len(result) == 1

    def test_search_configuration(self):
        self.require(ad_user=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_user_account(), self.ad_user_password())
        activate(creds)
        client = Client(domain)
        base = client.configuration_base()
        result = client.search('(objectClass=*)', base=base, scope='base')
        assert len(result) == 1

    def _delete_group(self, client, dn, server=None):
        try:
            client.delete(dn, server=server)
        except (ADError, LDAPError):
            pass

    def _create_group(self, client, name, server=None):
        attrs = []
        attrs.append(('cn', [name]))
        attrs.append(('sAMAccountName', [name]))
        attrs.append(('objectClass', ['group']))
        dn = 'cn=%s,cn=Users,%s' % (name, client.dn_from_domain_name(client.domain()))
        self._delete_group(client, dn, server=server)
        client.add(dn, attrs, server=server)
        return dn

    def _add_user_to_group(self, client, user, group):
        mods = []
        mods.append(('delete', 'member', [user]))
        try:
            client.modify(group, mods)
        except (ADError, LDAPError):
            pass
        mods = []
        mods.append(('add', 'member', [user]))
        client.modify(group, mods)

    def test_incremental_retrieval_of_multivalued_attributes(self):
        self.require(ad_admin=True, expensive=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        user = self._create_user(client, 'test-usr')
        groups = []
        for i in range(2000):
            group = self._create_group(client, 'test-grp-%04d' % i)
            self._add_user_to_group(client, user, group)
            groups.append(group)
        result = client.search('(sAMAccountName=test-usr)')
        assert len(result) == 1
        dn, attrs = result[0]
        assert attrs.has_key('memberOf')
        assert len(attrs['memberOf']) == 2000
        self._delete_obj(client, user)
        for group in groups:
            self._delete_group(client, group)

    def test_paged_results(self):
        self.require(ad_admin=True, expensive=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        users = []
        for i in range(2000):
            user = self._create_user(client, 'test-usr-%04d' % i)
            users.append(user)
        result = client.search('(cn=test-usr-*)')
        assert len(result) == 2000
        for user in users:
            self._delete_obj(client, user)

    def test_search_rootdse(self):
        self.require(ad_user=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_user_account(), self.ad_user_password())
        activate(creds)
        locator = Locator()
        server = locator.locate(domain)
        client = Client(domain)
        result = client.search(base='', scope='base', server=server)
        assert len(result) == 1
        dns, attrs = result[0]
        assert attrs.has_key('supportedControl')
        assert attrs.has_key('supportedSASLMechanisms')

    def test_search_server(self):
        self.require(ad_user=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_user_account(), self.ad_user_password())
        activate(creds)
        locator = Locator()
        server = locator.locate(domain)
        client = Client(domain)
        result = client.search('(objectClass=user)', server=server)
        assert len(result) > 1

    def test_search_gc(self):
        self.require(ad_user=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_user_account(), self.ad_user_password())
        activate(creds)
        client = Client(domain)
        result = client.search('(objectClass=user)', scheme='gc')
        assert len(result) > 1
        for res in result:
            dn, attrs = res
            # accountExpires is always set, but is not a GC attribute
            assert 'accountExpires' not in attrs

    def test_set_password(self):
        self.require(ad_admin=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        user = self._create_user(client, 'test-usr-1')
        principal = 'test-usr-1@%s' % domain
        client.set_password(principal, 'Pass123')
        mods = []
        ctrl = AD_USERCTRL_NORMAL_ACCOUNT
        mods.append(('replace', 'userAccountControl', [str(ctrl)]))
        client.modify(user, mods)
        creds = Creds(domain)
        creds.acquire('test-usr-1', 'Pass123')
        assert_raises(ADError, creds.acquire, 'test-usr-1', 'Pass321')
        self._delete_obj(client, user)

    def test_set_password_target_pdc(self):
        self.require(ad_admin=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        locator = Locator()
        pdc = locator.locate(domain, role='pdc')
        user = self._create_user(client, 'test-usr-2', server=pdc)
        principal = 'test-usr-2@%s' % domain
        client.set_password(principal, 'Pass123', server=pdc)
        mods = []
        ctrl = AD_USERCTRL_NORMAL_ACCOUNT
        mods.append(('replace', 'userAccountControl', [str(ctrl)]))
        client.modify(user, mods, server=pdc)
        creds = Creds(domain)
        creds.acquire('test-usr-2', 'Pass123', server=pdc)
        assert_raises(ADError, creds.acquire, 'test-usr-2','Pass321',
                      server=pdc)
        self._delete_obj(client, user, server=pdc)

    def test_change_password(self):
        self.require(ad_admin=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        user = self._create_user(client, 'test-usr-3')
        principal = 'test-usr-3@%s' % domain
        client.set_password(principal, 'Pass123')
        mods = []
        ctrl = AD_USERCTRL_NORMAL_ACCOUNT
        mods.append(('replace', 'userAccountControl', [str(ctrl)]))
        mods.append(('replace', 'pwdLastSet', ['0']))
        client.modify(user, mods)
        client.change_password(principal, 'Pass123', 'Pass456')
        creds = Creds(domain)
        creds.acquire('test-usr-3', 'Pass456')
        assert_raises(ADError, creds.acquire, 'test-usr-3', 'Pass321')
        self._delete_obj(client, user)

    def test_change_password_target_pdc(self):
        self.require(ad_admin=True)
        domain = self.domain()
        creds = Creds(domain)
        creds.acquire(self.ad_admin_account(), self.ad_admin_password())
        activate(creds)
        client = Client(domain)
        locator = Locator()
        pdc = locator.locate(domain, role='pdc')
        user = self._create_user(client, 'test-usr-4', server=pdc)
        principal = 'test-usr-4@%s' % domain
        client.set_password(principal, 'Pass123', server=pdc)
        mods = []
        ctrl = AD_USERCTRL_NORMAL_ACCOUNT
        mods.append(('replace', 'userAccountControl', [str(ctrl)]))
        mods.append(('replace', 'pwdLastSet', ['0']))
        client.modify(user, mods, server=pdc)
        client.change_password(principal, 'Pass123', 'Pass456', server=pdc)
        creds = Creds(domain)
        creds.acquire('test-usr-4', 'Pass456', server=pdc)
        assert_raises(ADError, creds.acquire, 'test-usr-4', 'Pass321',
                             server=pdc)
        self._delete_obj(client, user, server=pdc)
