#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

import time
import random
import logging

import ldap
import dns.resolver
import dns.reversename
import dns.exception
from ad.protocol import netlogon
from ad.protocol.netlogon import Client as NetlogonClient
from ad.core.exception import Error as ADError


LDAP_PORT = 389
KERBEROS_PORT = 88
KPASSWD_PORT = 464


class Locator(object):
    """Locate domain controllers.
    
    The function of is class is to locate, select, and order domain
    controllers for a given domain.

    The default selection mechanism discards domain controllers that do not
    have a proper reverse DNS name set. These domain controllers are not
    usable with SASL/GSSAPI that uses hostname canonicalisation based on
    reverse DNS.
    
    The default ordering mechanism has two different policies:

    - For local domain controllers we order on the priority and weight that
      has been configured for the SRV records.
    - For remote domain controllers we order on timing only and we ignore
      priority and weight. This may or may not be what you want. From my
      experience, priorities and weights are often not set up at all. In this
      situation is is preferable to use timing information to order domain
      controllers.

    Both policies (selection and ordering) can be changed by subclassing this
    class.
    """

    _maxservers = 3
    _timeout = 300  # cache entries for 5 minutes

    def __init__(self, site=None):
        """Constructor."""
        self.m_site = site
        self.m_site_detected = False
        self.m_logger = logging.getLogger('ad.core.locate')
        self.m_cache = {}
        self.m_timeout = self._timeout

    def locate(self, domain, role=None):
        """Locate one domain controller."""
        servers = self.locate_many(domain, role, maxservers=1)
        if not servers:
            m = 'Could not locate domain controller'
            raise ADError, m
        return servers[0]

    def locate_many(self, domain, role=None, maxservers=None):
        """Locate a list of up to `maxservers' of domain controllers."""
        if role is None:
            role = 'dc'
        if maxservers is None:
            maxservers = self._maxservers
        if role not in ('dc', 'gc', 'pdc'):
            raise ValueError, 'Role should be one of "dc", "gc" or "pdc".'
        if role == 'pdc':
            maxservers = 1
        domain = domain.upper()
        self.m_logger.debug('locating domain controllers for %s (role %s)' %
                            (domain, role))
        key = (domain, role)
        if key in self.m_cache:
            stamp, nrequested, servers = self.m_cache[key]
            now = time.time()
            if now - stamp < self._timeout and nrequested >= maxservers:
                self.m_logger.debug('domain controllers found in cache')
                return servers
        self.m_logger.debug('domain controllers not in cache, going to network')
        servers = []
        candidates = []
        if self.m_site is None and not self.m_site_detected:
            self.m_site = self._detect_site(domain)
            self.m_site_detected = True
        if self.m_site and role != 'pdc':
            query = '_ldap._tcp.%s._sites.%s._msdcs.%s' % \
                    (self.m_site, role, domain.lower())
            answer = self._dns_query(query, 'SRV')
            candidates += self._order_dns_srv(answer)
        query = '_ldap._tcp.%s._msdcs.%s' % (role, domain.lower())
        answer = self._dns_query(query, 'SRV')
        candidates += self._order_dns_srv(answer)
        addresses = self._extract_addresses_from_srv(candidates)
        addresses = self._remove_duplicates(addresses)
        replies = []
        netlogon = NetlogonClient()
        for i in range(0, len(addresses), maxservers):
            for addr in addresses[i:i+maxservers]:
                addr = (addr[0], LDAP_PORT)  # in case we queried for GC
                netlogon.query(addr, domain)
            replies += netlogon.call()
            if self._sufficient_domain_controllers(replies, role, maxservers):
                break
        result = self._select_domain_controllers(replies, role, maxservers,
                                                 addresses)
        servers = self._extract_addresses_from_netlogon(result)
        self.m_logger.debug('found %d domain controllers' % len(servers))
        now = time.time()
        self.m_cache[key] = (now, maxservers, servers)
        return servers

    def check_domain_controller(self, server, domain, role):
        """Ensure that `server' is a domain controller for `domain' and has
        role `role'.
        """
        addr = (server, LDAP_PORT)
        client = NetlogonClient()
        client.query(addr, domain.upper())
        result = client.call()
        if len(result) != 1:
            return False
        reply = result[0]
        result = self._check_domain_controller(reply, role)
        return result

    def _dns_query(self, query, type):
        """Perform a DNS query."""
        self.m_logger.debug('DNS query %s type %s' % (query, type))
        try:
            answer = dns.resolver.query(query, type)
        except dns.exception.DNSException, err:
            answer = []
            self.m_logger.error('DNS query error: %s' % (str(err) or err.__doc__))
        else:
            self.m_logger.debug('DNS query returned %d results' % len(answer))
        return answer

    def _detect_site(self, domain):
        """Detect our site using the netlogon protocol."""
        self.m_logger.debug('detecting site')
        query = '_ldap._tcp.%s' % domain.lower()
        answer = self._dns_query(query, 'SRV')
        servers = self._order_dns_srv(answer)
        addresses = self._extract_addresses_from_srv(servers)
        replies = []
        netlogon = NetlogonClient()
        for i in range(0, len(addresses), 3):
            for addr in addresses[i:i+3]:
                self.m_logger.debug('NetLogon query to %s' % addr[0])
                netlogon.query(addr, domain)
            replies += netlogon.call()
            self.m_logger.debug('%d replies' % len(replies))
            if replies >= 3:
                break
        if not replies:
            self.m_logger.error('could not detect site')
            return
        sites = {}
        for reply in replies:
            try:
                sites[reply.client_site] += 1
            except KeyError:
                sites[reply.client_site] = 1
        sites = [ (value, key) for key,value in sites.items() ]
        sites.sort()
        self.m_logger.debug('site detected as %s' % sites[-1][1])
        return sites[0][1]

    def _order_dns_srv(self, answer):
        """Order the results of a DNS SRV query."""
        answer = list(answer)
        answer.sort(lambda x,y: x.priority - y.priority)
        result = []
        for i in range(len(answer)):
            if i == 0:
                low = i
                prio = answer[i].priority
            if i > 0 and answer[i].priority != prio:
                result += self._srv_weighted_shuffle(answer[low:i])
                low = i
                prio = answer[i].priority
            elif i == len(answer)-1:
                result += self._srv_weighted_shuffle(answer[low:])
        return result

    def _srv_weighted_shuffle(self, answer):
        """Do a weighted shuffle on the SRV query result `result'."""
        result = []
        for i in range(len(answer)):
            total = 0
            cumulative = []
            for j in range(len(answer)):
                total += answer[j].weight
                cumulative.append((total, j))
            rnd = random.randrange(0, total)
            for j in range(len(answer)):
                if rnd < cumulative[j][0]:
                    k = cumulative[j][1]
                    result.append(answer[k])
                    del answer[k]
                    break
        return result

    def _extract_addresses_from_srv(self, answer):
        """Extract IP addresses from a DNS SRV query answer."""
        result = [ (a.target.to_text(), a.port) for a in answer ]
        return result

    def _remove_duplicates(self, servers):
        """Remove duplicates for `servers', keeping the order."""
        dict = {}
        result = []
        for srv in servers:
            if srv not in dict:
                result.append(srv)
                dict[srv] = True
        return result

    def _extract_addresses_from_netlogon(self, replies):
        """Return (hostname, port) tuples from a list of netlogon replies."""
        result = [ r.hostname for r in replies ]
        return result

    def _check_domain_controller(self, reply, role):
        """Check that `server' is a domain controller for `domain' and has
        role `role'.
        """
        self.m_logger.debug('Checking controller %s for domain %s role %s' %
                            (reply.q_hostname, reply.q_domain, role))
        answer = self._dns_query(reply.q_hostname, 'A')
        if len(answer) != 1:
            self.m_logger.error('Forward DNS returned %d entries (need 1)' %
                                len(anser))
            return False
        address = answer[0].address
        revname = dns.reversename.from_address(address)
        answer = self._dns_query(revname, 'PTR')
        if len(answer) != 1:
            self.m_logger.error('Reverse DNS returned %d entries (need 1)'
                                % len(answer))
            return False
        hostname = answer[0].target.to_text()
        answer = self._dns_query(hostname, 'A')
        if len(answer) != 1:
            self.m_logger.error('Second fwd DNS returned %d entries (need 1)'
                                % len(answer))
            return False
        if answer[0].address != address:
            self.m_logger.error('Second forward DNS does not match first')
            return False
        if role == 'gc' and not (reply.flags & netlogon.SERVER_GC) or \
                role == 'pdc' and not (reply.flags & netlogon.SERVER_PDC) or \
                role == 'dc' and not (reply.flags & netlogon.SERVER_LDAP):
            self.m_logger.error('Role does not match')
            return False
        if reply.q_domain.lower() != reply.domain.lower():
            self.m_logger.error('Domain does not match')
            return False
        self.m_logger.debug('Controller is OK')
        return True

    def _sufficient_domain_controllers(self, replies, role, maxservers):
        """Return True if there are sufficient domain controllers in `replies'
        to satisfy `maxservers'."""
        total = 0
        for reply in replies:
            if not hasattr(reply, 'checked'):
                checked = self._check_domain_controller(reply, role)
                reply.checked = checked
            if reply.checked:
                total += 1
        return total >= maxservers

    def _select_domain_controllers(self, replies, role, maxservers, addresses):
        """Select up to `maxservers' domain controllers from `replies'. The
        `addresses' argument is the ordered list of addresses from DNS SRV
        resolution. It can be used to obtain SRV ordering information.
        """
        local = []
        remote = []
        for reply in replies:
            assert hasattr(reply, 'checked')
            if not reply.checked:
                continue
            if self.m_site.lower() == reply.server_site.lower():
                local.append(reply)
            else:
                remote.append(reply)
        local.sort(lambda x,y: cmp(addresses.index((x.q_hostname, x.q_port)),
                                   addresses.index((y.q_hostname, y.q_port))))
        remote.sort(lambda x,y: cmp(x.q_timing, y.q_timing))
        self.m_logger.debug('Local DCs: %s' % ', '.join(['%s:%s' %
                                (x.q_hostname, x.q_port) for x in local]))
        self.m_logger.debug('Remote DCs: %s' % ', '.join(['%s:%s' %
                                (x.q_hostname, x.q_port) for x in remote]))
        result = local + remote
        result = result[:maxservers]
        self.m_logger.debug('Selected DCs: %s' % ', '.join(['%s:%s' %
                                (x.q_hostname, x.q_port) for x in result]))
        return result
