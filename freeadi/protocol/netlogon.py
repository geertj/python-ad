#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import time
import errno
import socket
import select
import random

from freeadi.util import misc
from freeadi.protocol import rfc1035, asn1, ldap


SERVER_PDC = 0x1
SERVER_GC = 0x4
SERVER_LDAP = 0x8
SERVER_DS = 0x10
SERVER_KDC = 0x20
SERVER_TIMESERV = 0x40
SERVER_CLOSEST = 0x80
SERVER_WRITABLE = 0x100
SERVER_GOOD_TIMESERV = 0x200


class Error(Exception):
    """Netlogon error."""


class Reply(object):
    """The result of a NetLogon RPC."""

    def __init__(self, **kwargs):
        """Constructor."""
        for key in kwargs:
            setattr(self, key, kwargs[key])


class Decoder(object):
    """Netlogon decoder."""

    def start(self, buffer):
        """Start decoding `buffer'."""
        self.m_input = buffer
        self.m_offset = 0

    def parse(self):
        """Parse a netlogon reply."""
        type = self._decode_uint32()
        flags = self._decode_uint32()
        domain_guid = self._read_bytes(16)
        forest = self._decode_rfc1035()
        domain = self._decode_rfc1035()
        hostname = self._decode_rfc1035()
        netbios_domain = self._decode_rfc1035()
        netbios_hostname = self._decode_rfc1035()
        user = self._decode_rfc1035()
        client_site = self._decode_rfc1035()
        server_site = self._decode_rfc1035()
        return Reply(type=type, flags=flags, domain_guid=domain_guid,
                     forest=forest, domain=domain, hostname=hostname,
                     netbios_domain=netbios_domain,
                     netbios_hostname=netbios_hostname, user=user,
                     client_site=client_site, server_site=server_site)

    def _decode_rfc1035(self):
        """Decompress an RFC1035 (section 4.1.4) compressed string."""
        try:
            value, offset = rfc1035.decompress(self.m_input, self.m_offset)
        except ValueError, err:
            raise Error, err.message
        self.m_offset = offset
        return value

    def _try_convert_int(self, value):
        """Try to convert `value' to an integer."""
        try:
            value = int(value)
        except OverflowError:
            pass
        return value

    def _decode_uint32(self):
        """Decode a 32-bit unsigned little endian integer from the current
        offset."""
        value = 0L
        for i in range(4):
            byte = self._read_byte()
            value |= (long(ord(byte)) << i*8)
        value = self._try_convert_int(value)
        return value

    def _read_byte(self, offset=None):
        """Read a single byte from the input."""
        if offset is None:
            offset = self.m_offset
            update_offset = True
        else:
            update_offset = False
        byte = self.m_input[offset]
        if update_offset:
            self.m_offset += 1
        return byte

    def _read_bytes(self, count, offset=None):
        """Return the next `count' bytes of input. Raise error on
        end-of-input."""
        if offset is None:
            offset = self.m_offset
            update_offset = True
        else:
            update_offset = False
        bytes = self.m_input[offset:offset+count]
        if len(bytes) != count:
            raise Error, 'Premature end of input.'
        if update_offset:
            self.m_offset += count
        return bytes


class Client(object):
    """A client for the netlogon service.

    This client can make multiple simultaneous netlogon calls.
    """

    _timeout = 3
    _retries = 3
    _bufsize = 8192

    def __init__(self):
        """Constructor."""
        self.m_socket = None
        self.m_queries = {}

    def query(self, addr, domain):
        """Add the Netlogon query to `addr' for `domain'."""
        hostname, port = addr
        addr = (socket.gethostbyname(hostname), port)
        self.m_queries[addr] = [hostname, port, domain, None]

    def call(self, timeout=None, retries=None):
        """Wait for results for `timeout' seconds."""
        if timeout is None:
            timeout = self._timeout
        if retries is None:
            retries = self._retries
        result = []
        self._create_socket()
        for i in range(retries):
            if not self.m_queries:
                break
            self._send_all_requests()
            result += self._wait_for_replies(timeout)
        self._close_socket()
        self.m_queries = {}
        return result

    def _create_socket(self):
        """Create an UDP socket for `server':`port'."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 0))
        self.m_socket = sock

    def _close_socket(self):
        """Close the UDP socket."""
        self.m_socket.close()
        self.m_socket = None

    def _create_message_id(self):
        """Create a new sequence number."""
        return random.randint(0, 2**31-1)

    def _send_all_requests(self):
        """Send requests to all hosts."""
        for addr in self.m_queries:
            domain = self.m_queries[addr][2]
            msgid = self._create_message_id()
            self.m_queries[addr][3] = msgid
            packet = self._create_netlogon_query(domain, msgid)
            self.m_socket.sendto(packet, 0, addr)

    def _wait_for_replies(self, timeout):
        """Wait one single timeout on all the sockets."""
        begin = time.time()
        end = begin + timeout
        replies = []
        while True:
            if not self.m_queries:
                break
            timeleft = end - time.time()
            if timeleft <= 0:
                break
            fds = [ self.m_socket.fileno() ]
            result = select.select(fds, [], [], timeleft)
            if not result[0]:
                continue  # timeout
            assert fds == result[0]
            while True:
                if not self.m_queries:
                    break
                try:
                    data, addr = self.m_socket.recvfrom(self._bufsize,  
                                                        socket.MSG_DONTWAIT)
                except socket.error, err:
                    error = err.args[0]
                    if error == errno.EINTR:
                        continue  # signal interrupt
                    elif error == errno.EAGAIN:
                        break  # no data available now
                    else:
                        raise Error, str(err)  # unrecoverable
                try:
                    hostname, port, domain, msgid = self.m_queries[addr]
                except KeyError:
                    continue  # someone sent us an erroneous datagram?
                try:
                    id, opcode = self._parse_message_header(data)
                except (asn1.Error, ldap.Error, Error):
                    continue
                if id != msgid:
                    continue
                del self.m_queries[addr]
                try:
                    reply = self._parse_netlogon_reply(data)
                except (asn1.Error, ldap.Error, Error):
                    continue
                if not reply:
                    continue
                reply.orig_hostname = hostname
                reply.port = port
                reply.address = addr[0]
                timing = time.time() - begin
                reply.timing = timing
                replies.append(reply)
        return replies

    def _create_netlogon_query(self, domain, msgid):
        """Create a netlogon query for `domain'."""
        client = ldap.Client()
        hostname = misc.hostname()
        filter = '(&(DnsDomain=%s)(Host=%s)(NtVer=\\06\\00\\00\\00))' % \
                 (domain, hostname)
        attrs = ('NetLogon',)
        query = client.create_search_request('', filter, attrs=attrs,
                                             scope=ldap.SCOPE_BASE, msgid=msgid)
        return query

    def _parse_message_header(self, reply):
        """Parse an LDAP header and return the messageid and opcode."""
        client = ldap.Client()
        msgid, opcode = client.parse_message_header(reply)
        return msgid, opcode

    def _parse_netlogon_reply(self, reply):
        """Parse a netlogon reply."""
        client = ldap.Client()
        messages = client.parse_search_result(reply)
        if not messages:
            return
        msgid, dn, attrs = messages[0]
        if not attrs.get('netlogon'):
            raise Error, 'No netlogon attribute received.'
        data = attrs['netlogon'][0]
        decoder = Decoder()
        decoder.start(data)
        result = decoder.parse()
        return result
