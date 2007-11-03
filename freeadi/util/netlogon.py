#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.util import rfc1035


class Error(Exception):
    """Netlogon error."""


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
        nb_domain = self._decode_rfc1035()
        nb_hostname = self._decode_rfc1035()
        user = self._decode_rfc1035()
        client_site = self._decode_rfc1035()
        server_site = self._decode_rfc1035()
        return (forest, domain, client_site, server_site)

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
