#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import math
import signal

from freeadi.test.base import BaseTest
from freeadi.core.locate import Locator
from threading import Timer


class SRV(object):
    """SRV record for Locator testing."""

    def __init__(self, priority=0, weight=100, target=None, port=None):
        self.priority = priority
        self.weight = weight
        self.target = target
        self.port = port


class TestLocator(BaseTest):
    """Test suite for Locator."""

    def test_simple(self):
        if not self.online_tests_allowed() \
                or not self.administrator_tests_allowed():
            return
        domain = self.domain()
        loc = Locator()
        result = loc.locate_many(domain)
        assert len(result) > 0
        result = loc.locate_many(domain, role='gc')
        assert len(result) > 0
        result = loc.locate_many(domain, role='pdc')
        assert len(result) == 1

    def test_network_failure(self):
        if not self.administrator_tests_allowed() \
                or not self.online_tests_allowed() \
                or not self.root_tests_allowed() \
                or not self.firewall_tests_allowed \
                or not self.iptables_supported():
            return
        domain = self.domain()
        loc = Locator()
        # Block outgoing DNS and CLDAP traffic and enable it after 3 seconds.
        # Locator should be able to handle this.
        self.remove_network_blocks()
        self.block_outgoing_traffic('tcp', 53)
        self.block_outgoing_traffic('udp', 53)
        self.block_outgoing_traffic('udp', 389)
        t = Timer(3, self.remove_network_blocks); t.start()
        result = loc.locate_many(domain)
        assert len(result) > 0

    def test_order_dns_srv_priority(self):
        srv = [ SRV(10), SRV(0), SRV(10), SRV(20), SRV(100), SRV(5) ]
        loc = Locator()
        result = loc._order_dns_srv(srv)
        prio = [ res.priority for res in result ]
        sorted = prio[:]
        sorted.sort()
        assert prio == sorted

    def test_order_dns_srv_weight(self):
        n = 10000
        w = (100, 50, 25)
        sumw = sum(w)
        count = {}
        for x in w:
            count[x] = 0
        loc = Locator()
        srv = [ SRV(0, x) for x in w ]
        for i in range(n):
            res = loc._order_dns_srv(srv)
            count[res[0].weight] += 1
        print count

        def stddev(n, p):
            # standard deviation of binomial distribution
            return math.sqrt(n*p*(1-p))

        for x in w:
            p = float(x)/sumw
            # 6 sigma this gives a 1 per 100 million chance of wrongly
            # asserting an error here.
            assert abs(count[x] - n*p) < 6 * stddev(n, p)

    def test_detect_site(self):
        if not self.online_tests_allowed() \
                or not self.administrator_tests_allowed():
            return
        loc = Locator()
        domain = self.domain()
        site = loc._detect_site(domain)
        assert site is not None
