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
import socket

from ad.core.exception import Error as ADError
from ad.core.object import factory, instance
from ad.core.creds import Creds
from ad.core.locate import Locator

# LDAP Constants

SCOPE_BASE = ldap.SCOPE_BASE
SCOPE_ONELEVEL = ldap.SCOPE_ONELEVEL
SCOPE_SUBTREE = ldap.SCOPE_SUBTREE

MOD_ADD = ldap.MOD_ADD
MOD_REPLACE = ldap.MOD_REPLACE
MOD_DELETE = ldap.MOD_DELETE

# AD Constants

CTRL_ACCOUNT_DISABLED = 0x2
CTRL_NORMAL_ACCOUNT = 0x200
CTRL_WORKSTATION_ACCOUNT = 0x1000
CTRL_DONT_EXPIRE_PASSWORD = 0x10000


class Client(object):
    """Active Directory Client

    This class implements a client interface to AD. It provides LDAP
    operations, Kerberos operations and more.
    """

    _timelimit = 0
    _sizelimit = 0
    _referrals = False

    def __init__(self, domain):
        """Constructor."""
        self.m_domain = domain
        self.m_root = None
        self.m_contexts = None
        self.m_locator = None

    def _locator(self):
        """Return our resource locator."""
        if self.m_locator is None:
            self.m_locator = factory(Locator)
        return self.m_locator

    def _check_credentials(self):
        """Ensure we have AD credentials."""
        creds = instance(Creds)
        if not creds.principal():
            m = 'No current credentials or credentials not activated.'
            raise ADError, m

    def _create_ldap_uri(self, servers):
        """Return an LDAP uri for the server list `servers'."""
        parts = [ 'ldap://%s/' % srv for srv in servers ]
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
            self._check_credentials()
            sasl = ldap.sasl.sasl({}, 'GSSAPI')
            ld.sasl_interactive_bind_s('', sasl)
        return ld

    def _ldap_connection(self, context):
        """Return the (cached) LDAP connection for a naming context."""
        assert context in self.m_contexts
        if self.m_contexts[context] is None:
            locator = self._locator()
            domain = self.domain_name_from_dn(context)
            servers = locator.locate_many(domain)
            uri = self._create_ldap_uri(servers)
            conn = self._create_ldap_connection(uri)
            self.m_contexts[context] = conn
        return self.m_contexts[context]

    def close(self):
        """Close any active LDAP connection."""
        for ctx in self.m_contexts:
            conn = self.m_contexts[ctx]
            if conn is not None:
                conn.unbind_s()
                self.m_contexts[ctx] = None

    def domain_name_from_dn(self, dn):
        """Given a DN, return a domain."""
        parts = ldap.str2dn(dn)
        parts.reverse()
        domain = []
        for part in parts:
            type,value,flags = part[0]  # weird API..
            if type != 'dc':
                break
            domain.insert(0, value)
        return '.'.join(domain)

    def dn_from_domain_name(self, name):
        """Given a domain name, return a DN."""
        parts = name.split('.')
        dn = [ 'dc=%s' % p for p in parts ]
        dn = ','.join(dn)
        return dn

    def root(self):
        """Return the root of the forest."""
        if self.m_root:
            return self.m_root
        locator = self._locator()
        servers = locator.locate_many(self.m_domain)
        uri = self._create_ldap_uri(servers)
        conn = self._create_ldap_connection(uri, bind=False)
        try:
            attrs = ('rootDomainNamingContext',)
            result = conn.search_s('', ldap.SCOPE_BASE, attrlist=attrs)
            if not result:
                raise ADError, 'Could not search rootDSE of domain.'
        finally:
            conn.unbind_s()
        dn, attrs = result[0]
        nc = attrs['rootDomainNamingContext'][0]
        self.m_root = self.domain_name_from_dn(nc)
        return self.m_root

    def _init_contexts(self):
        """Initialize naming contexts."""
        if self.m_contexts is not None:
            return
        root = self.root()
        locator = self._locator()
        servers = locator.locate_many(self.m_domain)
        uri = self._create_ldap_uri(servers)
        conn = self._create_ldap_connection(uri, bind=False)
        try:
            attrs = ('namingContexts',)
            result = conn.search_s('', ldap.SCOPE_BASE, attrlist=attrs)
            if not result:
                raise ADError, 'Could not search rootDSE of forest root.'
        finally:
            conn.unbind_s()
        dn, attrs = result[0]
        contexts = {}
        for nc in attrs['namingContexts']:
            nc = nc.lower()
            domain = self.domain_name_from_dn(nc)
            contexts[nc] = None
        self.m_contexts = contexts

    def contexts(self):
        """Return a list of all naming contexts."""
        if self.m_contexts is None:
            self._init_contexts()
        return self.m_contexts.keys()

    def _resolve_context(self, base):
        """Resolve a base dn to a naming context."""
        if self.m_contexts is None:
            self._init_contexts()
        context = ''
        base = base.lower()
        for ctx in self.m_contexts:
            if base.endswith(ctx) and len(ctx) > len(context):
                context = ctx
        if not context:
            m = 'No valid naming context for base %s' % base
            raise ADError, m
        return context

    def _check_search_attrs(self, attrs):
        """Check validity of the `attrs' argument to search()."""
        if not isinstance(attrs, list) or not isinstance(attrs, tuple):
            raise ADError, 'Expecting sequence of strings.'
        for item in attrs:
            if not isinstance(item, str):
                raise ADError, 'Expecting sequence of strings.'

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
        context = self._resolve_context(dn)
        conn = self._ldap_connection(context)
        while hi != '*':
            try:
                hi = int(hi)
            except ValueError:
                m = 'Error while retrieving multi-valued attributes.'
                raise ADError, m
            rqattrs = ('%s;range=%s-*' % (type, hi+1),)
            filter = '(distinguishedName=%s)' % dn
            result = conn.search_s(context, SCOPE_SUBTREE, filter, rqattrs)
            if not result:
                # Object deleted?
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

    def search(self, filter=None, base=None, scope=None, attrs=None):
        """Search Active Directory and return a list of objects.

        The `filter' argument specifies an RFC 2254 search filter. If it is
        not provided, the default is '(objectClass=*)'.  `base' is the search
        base and defaults to the base of the current domain.  `scope' is the
        search scope and must be one of 'base', 'one' or 'subtree'. The
        default scope is 'substree'. `attrs' is the attribute list to
        retrieve. The default is to retrieve all attributes.
        """
        if filter is None:
            filter = '(objectClass=*)'
        if base is None:
            base = self.dn_from_domain_name(self.domain())
        if scope is None:
            scope = SCOPE_SUBTREE
        if attrs is not None:
            self._check_search_attrs(attrs)
        context = self._resolve_context(base)
        conn = self._ldap_connection(context)
        result = conn.search_s(base, scope, filter, attrs)
        result = self._remove_empty_search_entries(result)
        result = self._process_range_subtypes(result)
        return result

    def _check_add_list(self, attrs):
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

    def add(self, dn, attrs):
        """Add a new object to Active Directory.
        
        The object is createdwith a distinguished name `dn' and with attribute
        `attrs'.  The `attrs' parameter must be a list of (type, values)
        2-tuples. The type component is the LDAP attribute name and must be a
        string. The values component is the LDAP attribute values and must be
        a list of strings.
        """
        self._check_add_list(attrs)
        context = self._resolve_context(dn)
        conn = self._ldap_connection(context)
        conn.add_s(dn, attrs)

    def _check_modify_list(self, mods):
        """Check the `mods' argument to modify()."""
        if not isinstance(mods, list) and not isinstance(mods, tuple):
            raise TypeError, 'Expecting list of 3-tuples.'
        for item in mods:
            if not isinstance(item, tuple) and not isinstance(item, list) \
                    or not len(item) == 3:
                raise TypeError, 'Expecting list of 3-tuples.'
        for op,type,values in mods:
            if not op in (MOD_ADD, MOD_REPLACE, MOD_DELETE):
                raise TypeError, 'List items must be 3-tuple of (op, str, [str]).'
            if not isinstance(type, str):
                raise TypeError, 'List items must be 2-tuple of (op, str, [str]).'
            if not isinstance(values, list) and not isinstance(values, tuple):
                raise TypeError, 'List items must be 2-tuple of (op, str, [str]).'
            for val in values:
                if not isinstance(val, str):
                    raise TypeError, 'List items must be 2-tuple of (str, [str]).'

    def modify(self, dn, mods):
        """Modify the LDAP object `dn' with `mods'.
        
        The `mods' parameter must be a list of 3-tuples (op,type,value), with
        op being the operation (MOD_ADD, MOD_REPLACE or MOD_DELETE), type the
        attribute name and value a list of strings containing the attribute
        value(s).
        """
        self._check_modify_list(mods)
        context = self._resolve_context(dn)
        conn = self._ldap_connection(context)
        conn.modify_s(dn, mods)

    def delete(self, dn):
        """Delete the LDAP object referenced by `dn'."""
        context = self._resolve_context(dn)
        conn = self._ldap_connection(context)
        conn.delete_s(dn)

    def modrdn(self, dn, rdn):
        """Change the RDN of an object in Active Direcotry.

        `dn' specifies the object, `rdn' is the new RDN.
        """
        context = self._resolve_context(dn)
        conn = self._ldap_connection(context)
        conn.modrdn_s(dn, rdn)

    def domain(self):
        """Return the current domain."""
        return self.m_domain

    def set_password(self, principal, password):
        pass

    def change_password(self, principal, oldpw, newpw):
        pass
