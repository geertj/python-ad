#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

import dns
import dns.resolver
import dns.exception
import ldap
import ldap.sasl
import socket

from freeadi.exception import FreeADIError


class ADClient(object):
    """Active Directory Client

    This class implements a client interface to AD. It provides LDAP
    operations, DNS SRV server resolution, Kerberos functions and more.
    """

    def __init__(self, domain=None):
        """Constructor."""
        if domain:
            self.set_domain(domain)
        self.m_connection = None
        self.m_site = None
        self.m_site_resolved = False

    def _ldap_uri(self, servers):
        """Return an LDAP uri for the server list `servers'."""
        parts = [ 'ldap://%s:%d/' % (srv, prt) for (srv, prt) in servers ]
        uri = ' '.join(parts)
        return uri

    def _open_ldap_connection(self, uri):
        """Open a new LDAP connection and bind it using GSSAPI."""
        ld = ldap.initialize(uri)
        sasl = ldap.sasl.sasl({}, 'GSSAPI')
        ld.procotol_version = 3
        ld.sasl_interactive_bind_s('', sasl)
        return ld

    def _ldap_connection(self):
        """Return the (cached) LDAP connection for the domain."""
        if not self.m_connection:
            servers = self.resolve_server_list('ldap', 'tcp', max=3)
            uri = self._ldap_uri(servers)
            self.m_connection = self._open_ldap_connection(uri)
        return self.m_connection

    def close(self):
        """Close any active LDAP connection."""
        if self.m_connection:
            self.m_connection.unbind_s()
            self.m_connection = None

    def _check_credentials(self):
        """Check if the calling process has any Kerberos credentials."""

    def _ldap_value(self, value):
        """Return a python-ldap value list."""
        if not isinstance(value, tuple) and not isinstance(value, list):
            value = [value]
        return value

    def _ldap_scope(self, scope):
        """Return a python-ldap SCOPE_* constant for the string `scope'."""
        if scope == 'base':
            scope = ldap.SCOPE_BASE
        elif scope == 'onelevel':
            scope = ldap.SCOPE_ONELEVEL
        elif scope == 'subtree':
            scope = ldap.SCOPE_SUBTREE
        else:
            raise ValueError, 'Illegal search scope: %s' % scope
        return scope

    def _ldap_modify_operation(self, operation):
        """Return a python-ldap MOD_* constant for the string `operation'."""
        if operation == 'add':
            operation = ldap.MOD_ADD
        elif operation == 'delete':
            operation = ldap.MOD_DELETE
        elif operation == 'replace':
            operation = ldap.MOD_REPLACE
        else:
            raise ValueError, 'Illegal modify operation: %s' % operation
        return operation

    def _search_base(self, domain):
        """Return the base DN of the domain."""
        parts = domain.split('.')
        base = ','.join(['dc=%s' % part.lower() for part in parts])
        return base

    def search(self, filter=None, base=None, scope=None, attrs=None):
        """Search Active Directory and return a list of objects.

        The `filter' argument specifies an RFC 2254 search filter. If it is
        not provided, the default is '(objectClass=*)'.  `base' is the
        search base and defaults to the domain base.  `scope' is the search
        scope and must be one of 'base', 'one' or 'subtree'. The default
        scope is 'substree'. `attrs' is the attribute list to retrieve. The
        default is to retrieve all attributes.
        """
        if filter is None:
            filter = '(objectClass=*)'
        if base is None:
            base = self._search_base(self.domain())
        if scope is None:
            scope = 'subtree'
        scope = self._ldap_scope(scope)
        conn = self._ldap_connection()
        result = conn.search_s(base, scope, filter, attrs)
        return result

    def add(self, dn, attrs):
        """Add a new object to Active Directory.
        
        The object is created at `dn' with attribute `attrs'.  The
        `attrs' parameter must be a dictionary with string keys and
        string or list values. The key are the LDAP attributes, the
        values are the LDAP attribute values.
        """
        modlist = []
        for key in attrs:
            value = attrs[key]
            value = self._ldap_value(value)
            modlist.append((key, value))
        conn = self._ldap_connection()
        conn.add_s(dn, modlist)

    def modify(self, dn, mods):
        """Modify the LDAP object `dn' with `mods'.
        
        The `mods' parameter must be a list of 3-tuples op,key,value, with
        op being the operation ('add', 'delete' or 'replace'), key the
        attribute name and value a string or list of strings containing the
        attribute value(s).
        """
        modlist = []
        for op,key,value in mods:
            op = self._ldap_modify_operation(op)
            value = self._ldap_value(value)
            modlist.append((op,key,value))
        conn = self._ldap_connection()
        conn.modify_s(dn)

    def delete(self, dn):
        """Delete the LDAP object referenced by `dn'."""
        conn = self._ldap_connection()
        conn.delete_s(dn)

    def modrdn(self, dn, rdn):
        """Change the RDN of an object in Active Direcotry.

        `dn' specifies the object, `rdn' is the new RDN.
        """
        conn = self._ldap_connection()
        conn.modrdn_s(dn, rdn)

    def _hostname(self):
        """Return the host name.

        The host name is defined as the "short" host name. If the hostname as
        returned by gethostname() includes a domain, the part until the first
        period ('.') is returned.
        """
        hostname = socket.gethostname()
        if '.' in hostname:
            hostname = hostname.split('.')[0]
        return hostname

    def _address(self):
        """Return the IP address of the current host.
        
        The IP address is defined as the result of a DNS A query on the short
        host name.
        """
        hostname = self._hostname()
        try:
            answer = dns.resolver.query(hostname, 'A')
        except dns.exception.DNSException:
            raise FreeADIError, 'Could not resolve hostname in DNS'
        address = answer.rrset[0].address
        return address

    def _subnet(self, address, bits):
        """Return a CIDR subnet with `bits' bits for IP address `address'."""
        parts = address.split('.')
        if len(parts) != 4:
            raise ValueError, 'Illegal IP address: %s' % address
        parts = map(long, parts)
        address = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        mask = ((1L << bits) - 1) << (32 - bits)
        masked = address & mask
        parts = [masked >> 24, (masked >> 16) & 0xff,
                 (masked >> 8) & 0xff, masked & 0xff]
        # Older version of Python add an 'L' suffix to longs so convert to
        # int first.
        subnet = '.'.join(map(str, map(int, parts)))
        return subnet

    def _resolve_site(self):
        """Resolve the site code of the current system."""
        if self.m_site_resolved:
            return self.m_site  # can be None
        # Below we cannot use self.resolve_server_list() to get a list of LDAP
        # servers because that functions depends on this function to return a
        # site code. Instead we use the domain name itself, for which AD
        # maintains A records for all domain controllers.
        uri = self._ldap_uri([(self.domain().lower(), ldap.PORT)])
        conn = self._open_ldap_connection(uri)
        # Read the DN for the configuration naming context from the rootDSE.
        # In case our domain is a child domain, this naming context will be on
        # a different domain controller and we will need to reconnect.
        result = conn.search_s('', ldap.SCOPE_BASE)
        if not result:
            m = 'Could not read rootDSE for domain %s' % self.domain()
            raise FreeADIError, m
        dn, attrs = result[0]
        config = attrs['configurationNamingContext'][0]
        parts = config.lower().split(',')
        parts = [ s[3:] for s in parts if s.startswith('dc=') ]
        domain = '.'.join(parts)
        if domain != self.domain():
            conn.unbind_s()
            uri = self._ldap_uri([(domain, ldap.PORT)])
            conn = self._open_ldap_connection(uri)
        # For performance purposes we fire of one query to match for all
        # possible subnets, instead of firing off 16 individual queries.
        terms = []
        address = self._address()
        for i in range(16, 33):
            subnet = '%s/%s' % (self._subnet(address, i), i)
            terms.append('(cn=%s)' % subnet)
        query = '(&(objectClass=subnet)(|%s))' % ''.join(terms)
        # For some reason it is necessary to add the CN=Sites prefix to the
        # search base otherwise we get a reference.
        base = 'CN=Sites,%s' % config
        result = conn.search_s(base, ldap.SCOPE_SUBTREE, query)
        if result:
            sites = []
            for dn,attrs in result:
                bits = int(attrs['cn'][0].split('/')[1])
                site = attrs['siteObject'][0].split(',')[0][3:]
                sites.append((bits, site))
            sites.sort()
            self.m_site = sites[-1][1]
        else:
            self.m_site = None
        self.m_site_resolved = True
        return self.m_site

    def _srv_weighted_shuffle(result):
        """Do a weighted shuffle on the SRV query result `result'."""
        output = []
        for ix in range(len(result)):
            total = result[0][1]
            cumulative = [(result[0][1], 0)]
            for iy in range(1, len(result)):
                total += result[iy][1]
                cumulative.append((cumulative[-1][0] + result[iy][1], iy))
            rnd = random.randrange(0, total)
            for iy in range(0, len(result)):
                if rnd < cumulative[iy]:
                    iz = cumulative[iy][1]
                    output.append(result[iz])
                    del result[iz]
                    break
        return output

    def _srv_order_result(self, result):
        """Order an SRV query result on weight and priority."""
        if not result:
            return result
        result.sort()
        low = 0
        low_prio = result[0][0]
        for ix in range(1, len(result)):
            if result[ix][0] != low_prio:
                result[low:ix] = _srv_weighted_shuffle(result[low:ix])
                low = ix
                low_prio = result[ix][1]
        return result

    def resolve_server(self, service, protocol=None):
        """Resolve and return a server that implements `service' on
        `protocol'. `protocol' normally is either 'tcp' or 'udp'.
        """
        list = self.resolve_server_list(service, protocol)
        if not list:
            m = 'No server found for service %s/%s' % (service, protocol)
            raise FreeADIError, m
        server = list[0]
        return server

    def resolve_server_list(self, service, protocol='tcp', max=None):
        """Resolve a server list for a service.

        This function will return a list of servers for `service'. The list is
        ordered on the following criteria:
        - local servers take precendence of non-local servers
        - servers with a higher priority (= lower numeric priority value) take
          precendence over servers with a lower priority.
        - given equal locality and priority, the weight factor of the SRV record
          is used in a weighted shuffle that on average places servers with a
          higher priority earlier in the list.
        """
        site = self._resolve_site()
        domain = self.domain()
        if site is not None:
            query = '_%s._%s.%s._sites.dc._msdcs.%s' % \
                    (service, protocol, site, domain)
            answer = dns.resolver.query(query, 'SRV')
            answer = [ (r.priority, r.weight, r.target, r.port)
                       for r in answer ]
            answer = self._srv_order_result(answer)
            result = [ (target.to_text(), port)
                       for prio, weight, target, port in answer ]
        else:
            result = []
        query = '_%s._%s.%s' % (service, protocol, domain)
        answer = dns.resolver.query(query, 'SRV')
        answer = [ (r.priority, r.weight, r.target, r.port) for r in answer ]
        answer = self._srv_order_result(answer)
        result += [ (target.to_text(), port)
                    for prio, weight, target, port in answer
                    if (target.to_text(), port) not in result ]
        return result

    def domain(self):
        """Return the current domain."""
        if not self.m_domain:
            raise FreeADIError, 'Domain not set'
        return self.m_domain

    def set_domain(self, domain):
        """Set the domain to `domain'."""
        # Always keep the domain in upper case which is the convention for
        # Kerberos realms. When we need a DNS domain name we convert it to
        # lower case.
        self.m_domain = domain.upper()

    def netbios_name(self):
        """Return the NETBIOS name of the current domain."""
        pass

    def _krb5_library(self):
        if not self.m_krb5_library:
            self.m_krb5_library = Krb5Library()
        return self.m_krb5_library

    def set_password(self, principal, password):
        lib = self._krb5_library()
        context = Krb5Context()
        lib.krb5_init_context(byref(context))

    def change_password(self, pricipal, oldpw, newpw):
        pass

    def factory(cls):
        self = cls()
        self.set_domain(domain)
        return self

    factory = classmethod(factory) 
