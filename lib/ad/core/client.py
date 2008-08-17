#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

import re
import dns
import dns.resolver
import dns.exception
import ldap
import ldap.sasl
import ldap.controls
import socket

from ad.core.exception import Error as ADError
from ad.core.object import factory, instance
from ad.core.creds import Creds
from ad.core.locate import Locator
from ad.core.constant import LDAP_PORT, GC_PORT
from ad.protocol import krb5


class Client(object):
    """Active Directory Client

    This class implements a client interface to AD. It provides LDAP
    operations, Kerberos operations and more.
    """

    _timelimit = 0
    _sizelimit = 0
    _referrals = False
    _pagesize = 500

    def __init__(self, domain):
        """Constructor."""
        self.m_locator = None
        self.m_connections = None
        self.m_naming_contexts = None
        self.m_domain = self.dn_from_domain_name(domain)
        self.m_forest = None
        self.m_schema = None
        self.m_configuration = None

    def _locator(self):
        """Return our resource locator."""
        if self.m_locator is None:
            self.m_locator = factory(Locator)
        return self.m_locator

    def _credentials(self):
        """Return our current AD credentials."""
        creds = instance(Creds)
        if creds is None or not creds.principal():
            m = 'No current credentials or credentials not activated.'
            raise ADError, m
        return creds

    def _fixup_scheme(self, scheme):
        """Check an LDAP search scheme."""
        if scheme is None:
            scheme = 'ldap'
        elif isinstance(scheme, str):
            if scheme not in ('ldap', 'gc'):
                raise ValueError, 'Illegal scheme: %s' % scheme
        else:
            raise TypeError, 'Illegal scheme type: %s' % type(scheme)
        return scheme

    def _create_ldap_uri(self, servers, scheme=None):
        """Return an LDAP uri for the server list `servers'."""
        scheme = self._fixup_scheme(scheme)
        if scheme == 'ldap':
            port = LDAP_PORT
        elif scheme == 'gc':
            port = GC_PORT
        parts = [ 'ldap://%s:%d/' % (srv, port) for srv in servers ]
        uri = ' '.join(parts)
        return uri

    def _create_ldap_connection(self, uri, bind=True):
        """Open a new LDAP connection and optionally bind it using GSSAPI."""
        ld = ldap.initialize(uri)
        ld.procotol_version = 3
        ld.timelimit = self._timelimit
        ld.sizelimit = self._sizelimit
        ld.referrals = self._referrals
        if bind:
            sasl = ldap.sasl.sasl({}, 'GSSAPI')
            ld.sasl_interactive_bind_s('', sasl)
        return ld

    def domain_name_from_dn(self, dn):
        """Given a DN, return a domain."""
        parts = ldap.str2dn(dn)
        parts.reverse()
        domain = []
        for part in parts:
            type,value,flags = part[0]  # weird API..
            if type.lower() != 'dc':
                break
            domain.insert(0, value)
        return '.'.join(domain).upper()

    def dn_from_domain_name(self, name):
        """Given a domain name, return a DN."""
        parts = name.split('.')
        dn = [ 'dc=%s' % p for p in parts ]
        dn = ','.join(dn)
        return dn.lower()

    def _init_forest(self):
        """Initialize forest global settings."""
        if self.m_forest is not None:
            return
        locator = self._locator()
        servers = locator.locate_many(self.domain())
        uri = self._create_ldap_uri(servers)
        conn = self._create_ldap_connection(uri, bind=False)
        try:
            attrs = ('rootDomainNamingContext', 'schemaNamingContext',
                     'configurationNamingContext')
            result = conn.search_s('', ldap.SCOPE_BASE, attrlist=attrs)
            if not result:
                raise ADError, 'Could not search rootDSE of domain.'
        finally:
            conn.unbind_s()
        dn, attrs = result[0]
        self.m_forest = attrs['rootDomainNamingContext'][0]
        self.m_schema = attrs['schemaNamingContext'][0]
        self.m_configuration = attrs['configurationNamingContext'][0]

    def domain(self):
        """Return the domain name of the current domain."""
        return self.domain_name_from_dn(self.m_domain)

    def domain_base(self):
        """Return the base DN of the domain."""
        return self.m_domain

    def forest(self):
        """Return the domain name of the forest root."""
        if self.m_forest is None:
            self._init_forest()
        return self.domain_name_from_dn(self.m_forest)

    def forest_base(self):
        """Return the base DN of the forest root."""
        if self.m_forest is None:
            self._init_forest()
        return self.m_forest

    def schema_base(self):
        """Return the base DN of the schema naming_context."""
        if self.m_schema is None:
            self._init_forest()
        return self.m_schema

    def configuration_base(self):
        """Return the base DN of the configuration naming_context."""
        if self.m_configuration is None:
            self._init_forest()
        return self.m_configuration

    def _init_naming_contexts(self):
        """Initialize naming naming_contexts."""
        if self.m_naming_contexts is not None:
            return
        locator = self._locator()
        servers = locator.locate_many(self.domain())
        uri = self._create_ldap_uri(servers)
        conn = self._create_ldap_connection(uri)
        base = 'cn=Partitions,%s' % self.configuration_base()
        filter = '(objectClass=crossRef)'
        try:
            attrs = ('nCName',)
            result = conn.search_s(base, ldap.SCOPE_ONELEVEL, filter, attrs)
            if not result:
                raise ADError, 'Could not search rootDSE of forest root.'
        finally:
            conn.unbind_s()
        naming_contexts = []
        for res in result:
            dn, attrs = res
            nc = attrs['nCName'][0].lower()
            naming_contexts.append(nc)
        self.m_naming_contexts = naming_contexts

    def naming_contexts(self):
        """Return a list of all naming_contexts."""
        if self.m_naming_contexts is None:
            self._init_naming_contexts()
        return self.m_naming_contexts

    def domains(self):
        """Return a list of all domains in the forest."""
        domains = []
        for nc in self.naming_contexts():
            if nc.startswith('dc=domaindnszones') or \
                    nc.startswith('dc=forestdnszones') or \
                    nc.startswith('dc=tapi3directory') or \
                    nc.startswith('cn=schema') or \
                    nc.startswith('cn=configuration'):
                continue
            domains.append(self.domain_name_from_dn(nc))
        return domains

    def _resolve_naming_context(self, base):
        """Resolve a base dn to a directory naming_context."""
        naming_context = ''
        base = base.lower()
        for nc in self.naming_contexts():
            if base.endswith(nc) and len(nc) > len(naming_context):
                naming_context = nc
        return naming_context
    
    def _ldap_connection(self, base, server=None, scheme=None):
        """Return the (cached) LDAP connection for a naming naming_context."""
        naming_context = self._resolve_naming_context(base)
        scheme = self._fixup_scheme(scheme)
        if self.m_connections is None:
            self.m_connections = {}
        key = (naming_context, server, scheme)
        if key not in self.m_connections:
            locator = self._locator()
            if naming_context == '':
                assert server != None
                uri = self._create_ldap_uri([server])
                bind = False  # No need to bind for rootDSE
            else:
                domain = self.domain_name_from_dn(naming_context)
                if scheme == 'gc':
                    role = 'gc'
                elif scheme == 'ldap':
                    role = 'dc'
                if server is None:
                    servers = locator.locate_many(domain, role=role)
                    uri = self._create_ldap_uri(servers, scheme)
                else:
                    if not locator.check_domain_controller(server, domain, role):
                        raise ADError, 'Unsuitable server provided.'
                    uri = self._create_ldap_uri([server], scheme)
                creds = self._credentials()
                creds._resolve_servers_for_domain(domain)
                bind = True
            conn = self._create_ldap_connection(uri, bind)
            self.m_connections[key] = conn
        return self.m_connections[key]

    def close(self):
        """Close any active LDAP connection."""
        for conn in self.m_connections.values():
            conn.unbind_s()
        self.m_connections = None

    def _remove_empty_search_entries(self, result):
        """Remove empty search entries from a search result."""
        # What I have seen so far these entries are always LDAP referrals
        return filter(lambda x: x[0] is not None, result)

    re_range = re.compile('([^;]+);[Rr]ange=([0-9]+)(?:-([0-9]+|\\*))?')

    def _retrieve_all_ranges(self, dn, key, attrs):
        """Retrieve all ranges for a multivalued attributed."""
        assert key in attrs
        mobj = self.re_range.match(key)
        assert mobj is not None
        type, lo, hi = mobj.groups()
        values = attrs[key]
        conn = self._ldap_connection(dn)
        base = self._resolve_naming_context(dn)
        while hi != '*':
            try:
                hi = int(hi)
            except ValueError:
                m = 'Error while retrieving multi-valued attributes.'
                raise ADError, m
            rqattrs = ('%s;range=%s-*' % (type, hi+1),)
            filter = '(distinguishedName=%s)' % dn
            result = conn.search_s(base, ldap.SCOPE_SUBTREE, filter, rqattrs)
            if not result:
                # Object deleted? Assume it was and return no further
                # attributes.
                break
            dn2, attrs2 = result[0]
            for key2 in attrs2:
                mobj = self.re_range.match(key2)
                if mobj is None:
                    continue
                type2, lo2, hi2 = mobj.groups()
                if type2 == type and lo2 == str(hi+1):
                    break
            else:
                m = 'Error while retrieving multi-valued attributes.'
                raise ADError, m
            values += attrs2[key2]
            hi = hi2
        attrs[type] = values
        del attrs[key]

    def _process_range_subtypes(self, result):
        """Incremental retrieval of multi-valued attributes."""
        for dn,attrs in result:
            for key in attrs.keys():  # dict will be updated
                if self.re_range.match(key):
                    self._retrieve_all_ranges(dn, key, attrs)
        return result

    def _fixup_filter(self, filter):
        """Fixup the `filter' argument."""
        if filter is None:
            filter = '(objectClass=*)'
        elif not isinstance(filter, str):
            raise TypeError, 'Illegal filter type: %s' % type(filter)
        return filter

    def _fixup_base(self, base):
        """Fixup an ldap search base."""
        if base is None:
            base = self.dn_from_domain_name(self.domain())
        elif not isinstance(base, str):
            raise TypeError, 'Illegal search base type: %s' % type(base)
        return base

    def _fixup_scope(self, scope):
        """Check the ldap scope `scope'."""
        if scope is None:
            scope = ldap.SCOPE_SUBTREE
        elif scope == 'base':
            scope = ldap.SCOPE_BASE
        elif scope == 'onelevel':
            scope = ldap.SCOPE_ONELEVEL
        elif scope == 'subtree':
            scope = ldap.SCOPE_SUBTREE
        elif isinstance(scope, int):
            if scope not in (ldap.SCOPE_BASE, ldap.SCOPE_ONELEVEL,
                             ldap.SCOPE_SUBTREE):
                raise ValueError, 'Illegal scope: %s' % scope
        else:
            raise TypeError, 'Illegal scope type: %s' % type(scope)
        return scope

    def _fixup_attrs(self, attrs):
        """Check validity of the `attrs' argument to search()."""
        if attrs is None:
            pass
        elif isinstance(attrs, list) or isinstance(attrs, tuple):
            for item in attrs:
                if not isinstance(item, str):
                    raise TypeError, 'Expecting sequence of strings.'
        else:
            raise TypeError, 'Expecting sequence of strings.'
        return attrs

    def _search_with_paged_results(self, conn, filter, base, scope, attrs):
        """Perform an ldap search operation with paged results."""
        ctrl = ldap.controls.SimplePagedResultsControl(
                    ldap.LDAP_CONTROL_PAGE_OID, True, (self._pagesize, ''))
        result = []
        while True:
            msgid = conn.search_ext(base, scope, filter, attrs,
                                    serverctrls=[ctrl])
            type, data, msgid, ctrls = conn.result3(msgid)
            result += data
            rctrls = [ c for c in ctrls
                       if c.controlType == ldap.LDAP_CONTROL_PAGE_OID ]
            if not rctrls:
                m = 'Server does not honour paged results.'
                raise ADError, m
            est, cookie = rctrls[0].controlValue
            if not cookie:
                break
            ctrl.controlValue = (self._pagesize, cookie)
        return result

    def search(self, filter=None, base=None, scope=None, attrs=None,
               server=None, scheme=None):
        """Search Active Directory and return a list of objects.

        The `filter' argument specifies an RFC 2254 search filter. If it is
        not provided, the default is '(objectClass=*)'.  `base' is the search
        base and defaults to the base of the current domain.  `scope' is the
        search scope and must be one of 'base', 'one' or 'subtree'. The
        default scope is 'substree'. `attrs' is the attribute list to
        retrieve. The default is to retrieve all attributes.
        """
        filter = self._fixup_filter(filter)
        base = self._fixup_base(base)
        scope = self._fixup_scope(scope)
        atrs = self._fixup_attrs(attrs)
        scheme = self._fixup_scheme(scheme)
        if base == '':
            if server is None:
                m = 'A server must be specified when querying rootDSE'
                raise ADError, m
            if scope != ldap.SCOPE_BASE:
                m = 'Search scope must be base when querying rootDSE'
                raise ADError, m
        conn = self._ldap_connection(base, server, scheme)
        if base == '':
            # search rootDSE does not honour paged results
            result = conn.search_s(base, scope, filter, attrs)
        else:
            result = self._search_with_paged_results(conn, filter, base,
                                                     scope, attrs)
        result = self._remove_empty_search_entries(result)
        result = self._process_range_subtypes(result)
        return result

    def _fixup_add_list(self, attrs):
        """Check the `attrs' arguments to add()."""
        if not isinstance(attrs, list) and not isinstance(attrs, tuple):
            raise TypeError, 'Expecting list of 2-tuples %s.'
        for item in attrs:
            if not isinstance(item, tuple) and not isinstance(item, list) \
                    or not len(item) == 2:
                raise TypeError, 'Expecting list of 2-tuples.'
        for type,values in attrs:
            if not isinstance(type, str):
                raise TypeError, 'List items must be 2-tuple of (str, [str]).'
            if not isinstance(values, list) and not isinstance(values, tuple):
                raise TypeError, 'List items must be 2-tuple of (str, [str]).'
            for val in values:
                if not isinstance(val, str):
                    raise TypeError, 'List items must be 2-tuple of (str, [str]).'
        return attrs

    def add(self, dn, attrs, server=None):
        """Add a new object to Active Directory.
        
        The object is createdwith a distinguished name `dn' and with attribute
        `attrs'.  The `attrs' parameter must be a list of (type, values)
        2-tuples. The type component is the LDAP attribute name and must be a
        string. The values component is the LDAP attribute values and must be
        a list of strings.
        """
        attrs = self._fixup_add_list(attrs)
        conn = self._ldap_connection(dn, server)
        conn.add_s(dn, attrs)

    def _fixup_modify_operation(self, op):
        """Fixup an ldap modify operation."""
        if op == 'add':
            op = ldap.MOD_ADD
        elif op == 'replace':
            op = ldap.MOD_REPLACE
        elif op == 'delete':
            op = ldap.MOD_DELETE
        elif op not in (ldap.MOD_ADD, ldap.MOD_REPLACE, ldap.MOD_DELETE):
            raise ValueError, 'Illegal modify operation: %s' % op
        return op

    def _fixup_modify_list(self, mods):
        """Check the `mods' argument to modify()."""
        if not isinstance(mods, list) and not isinstance(mods, tuple):
            raise TypeError, 'Expecting list of 3-tuples.'
        for item in mods:
            if not isinstance(item, tuple) and not isinstance(item, list) \
                    or not len(item) == 3:
                raise TypeError, 'Expecting list of 3-tuples.'
        result = []
        for op,type,values in mods:
            op = self._fixup_modify_operation(op)
            if not isinstance(type, str):
                raise TypeError, 'List items must be 3-tuple of (str, str, [str]).'
            if not isinstance(values, list) and not isinstance(values, tuple):
                raise TypeError, 'List items must be 3-tuple of (str, str, [str]).'
            for val in values:
                if not isinstance(val, str):
                    raise TypeError, 'List item must be 3-tuple of (str, str, [str]).'
            result.append((op,type,values))
        return result

    def modify(self, dn, mods, server=None):
        """Modify the LDAP object `dn' with `mods'.
        
        The `mods' parameter must be a list of 3-tuples (op,type,value), with
        op being the operation (MOD_ADD, MOD_REPLACE or MOD_DELETE), type the
        attribute name and value a list of strings containing the attribute
        value(s).
        """
        mods = self._fixup_modify_list(mods)
        conn = self._ldap_connection(dn, server)
        conn.modify_s(dn, mods)

    def delete(self, dn, server=None):
        """Delete the LDAP object referenced by `dn'."""
        conn = self._ldap_connection(dn, server)
        conn.delete_s(dn)

    def modrdn(self, dn, newrdn, delold=True, server=None):
        """Change the RDN of an object in Active Direcotry.

        `dn' specifies the object, `newrdn' is the new RDN. The new RDN must
        be in the format of "rdn=value". If `delold' is True, the old value
        of the RDN is deleted, otherwise it is retained.
        """
        self.rename(dn, newrdn, delold=delold, server=server)

    def rename(self, dn, newrdn, newsuperior=None, delold=True, server=None):
        """Rename an object in AD, possibly moving it to another point in
        the directory. The `dn', `newrdn' and `delold' arguments are as with
        modrdn(). If the `newsuperior' argument is specified, it must be a
        DN and the object is moved there.
        """
        conn = self._ldap_connection(dn, server)
        conn.rename_s(dn, newrdn, newsuperior, delold)

    def set_password(self, principal, password, server=None):
        """Set the password of `principal' to `password'."""
        if '@' in principal:
            principal, domain = principal.split('@')
            domain = domain.upper()
        else:
            domain = self.domain()
        principal = '%s@%s' % (principal, domain)
        creds = self._credentials()
        if server is not None:
            creds._set_servers_for_domain(domain, [server])
        try:
            krb5.set_password(principal, password)
        except krb5.Error, err:
            raise ADError, str(err)
        if server is not None:
            creds._resolve_servers_for_domain(domain, force=True)

    def change_password(self, principal, oldpass, newpass, server=None):
        """Chagne the password of `principal' to `password'."""
        if '@' in principal:
            principal, domain = principal.split('@')
            domain = domain.upper()
        else:
            domain = self.domain()
        principal = '%s@%s' % (principal, domain)
        creds = self._credentials()
        if server is not None:
            creds._set_servers_for_domain(domain, [server])
        try:
            krb5.change_password(principal, oldpass, newpass)
        except krb5.Error, err:
            raise ADError, str(err)
        if server is not None:
            creds._resolve_servers_for_domain(domain, force=True)
