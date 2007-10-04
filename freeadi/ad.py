#
# This file is part of freeadi. Freeadi is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# Freeadi is copyright (c) 2007 by the freeadi authors. See the file "AUTHORS"
# for a complete overview.

import ldap
import ldap.sasl
import random
import freeadi


def detect_site_code():
    """Detect the AD site code."""

def _srv_weighted_shuffle(result):
    """Do a weighted shuffle."""
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

def _srv_order_result(result):
    """Order a list of SRV result."""
    if not result:
        return result
    # first order on priority
    result.sort()
    # second shuffle on weight
    low = 0
    low_prio = result[0][0]
    for ix in range(1, len(result)):
        if result[ix][0] != low_prio:
            result[low:ix] = _srv_weighted_shuffle(result[low:ix])
            low = ix
            low_prio = result[ix][1]
    return result

def get_server_list(service, protocol='tcp', max=None):
    """Return a server list.

    This function will return a list of servers for `service'. The list is
    ordered on the following criteria:
    - local servers take precendence of non-local servers
    - servers with a higher priority (= lower numeric priority value) take
      precendence over servers with a lower priority.
    - given equal locality and priority, the weight factor of the SRV record
      is used in a weighted shuffle that on average places servers with a
      higher priority earlier in the list.
    """
    config = freeadi.config.get_config()
    site = config['SITE']
    domain = config['DOMAIN']
    query = '_%s._%s.%s._sites.dc._msdcs.%s' % (service, protocol, site, domain)
    answer = dns.resolver.query(query, 'SRV')
    answer = [ r.priority, r.weight, r.target, r.port for r in result ]
    result = _srv_order_list(answer)
    query = '_%s._%s.%s' % (service, protocol, domain)
    answer = dns.resolver.query(query, 'SRV')
    answer = [ r.priority, r.weight, r.target, r.port for r in result ]
    answer = filter(lambda x: x in result, answer)
    result += _srv_order_list(answer)
    return result

def _open_ldap_connection(uri):
    """Return an LDAP connection object."""
    ld = ldap.initialize(uri)
    sasl_auth = ldap.sasl.sasl({}, 'GSSAPI')
    ld.protocol_version = 3
    ld.sasl_interactive_bind_s('', sasl_auth)

def ldap_search(filter, base=None, scope=None, attrs=None, uri=None):
    """Perform an LDAP search to the directory."""
    cfg = config.get_config()
    if base is None:
        base = cfg['BASEDN']
    if scope is None:
        scope = ldap.SCOPE_SUBTREE
    if uri is None:
        uri = cfg['URI']
    ld = _open_ldap_connection(uri)
    result = ld.search_s(base, scope, filter, attrs)
    ld.unbind_s()
