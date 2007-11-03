#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

Boolean = 0x01
Integer = 0x02
OctetString = 0x04
Null = 0x05
Enumerated = 0x0a
Sequence = 0x10
Set = 0x11

TypeConstructed = 0x20
TypePrimitive = 0x00

ClassUniversal = 0x00
ClassApplication = 0x40
ClassContext = 0x80
ClassPrivate = 0xc0


class Error(Exception):
    """ASN1 error"""


class Encoder(object):
    """A ASN.1 encoder. Uses DER encoding."""

    def __init__(self):
        """Constructor."""
        self.m_stack = None

    def start(self):
        """Start encoding."""
        self.m_stack = [[]]

    def enter(self, id, cls=None):
        """Start a constructed data value."""
        if self.m_stack is None:
            raise Error, 'Encoder not initialized. Call start() first.'
        if cls is None:
            cls = ClassUniversal
        self._emit_tag(id, TypeConstructed, cls)
        self.m_stack.append([])

    def leave(self):
        """Finish a constructed data value."""
        if self.m_stack is None:
            raise Error, 'Encoder not initialized. Call start() first.'
        if len(self.m_stack) == 1:
            raise Error, 'Tag stack is empty.'
        value = ''.join(self.m_stack[-1])
        del self.m_stack[-1]
        self._emit_length(len(value))
        self._emit(value)

    def write(self, value, id=None, cls=None):
        """Write a primitive data value."""
        if self.m_stack is None:
            raise Error, 'Encoder not initialized. Call start() first.'
        if id in (Sequence, Set):
            raise Error, 'Cannot write constructed type. Use enter().'
        if id is None:
            if isinstance(value, int) or isinstance(value, long):
                id = Integer
            elif isinstance(value, str) or isinstance(value, unicode):
                id = OctetString
            elif value is None:
                id = Null
        if cls is None:
            cls = ClassUniversal
        if id in (Integer, Enumerated):
            value = self._encode_integer(value)
        elif id == OctetString:
            value = self._encode_octet_string(value)
        elif id == Boolean:
            value = self._encode_boolean(value)
        elif id == Null:
            value = self._encode_null()
        length = len(value)
        self._emit_tag(id, TypePrimitive, cls)
        self._emit_length(length)
        self._emit(value)

    def output(self):
        """Return the encoded output."""
        if self.m_stack is None:
            raise Error, 'Encoder not initialized. Call start() first.'
        if len(self.m_stack) != 1:
            raise Error, 'Stack is not empty.'
        output = ''.join(self.m_stack[0])
        return output

    def _encode_boolean(self, value):
        """Encode a boolean."""
        return value and '\xff' or '\x00'

    def _encode_integer(self, value):
        """Encode an integer."""
        if value < 0:
            value = -value
            negative = True
            limit = 0x80
        else:
            negative = False
            limit = 0x7f
        values = []
        while value > limit:
            values.append(value & 0xff)
            value >>= 8
        values.append(value & 0xff)
        if negative:
            # create two's complement
            for i in range(len(values)):
                values[i] = 0xff - values[i]
            for i in range(len(values)):
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i != len(values)-1
                values[i] = 0x00
        values.reverse()
        values = map(chr, values)
        return ''.join(values)

    def _encode_octet_string(self, value):
        """Encode an octetstring."""
        # Use the primitive encoding
        return value 

    def _encode_null(self):
        """Encode a Null value."""
        return ''

    def _emit_tag(self, id, typ, cls):
        """Emit a tag."""
        if id < 31:
            self._emit_tag_short(id, typ, cls)
        else:
            self._emit_tag_long(id, typ, cls)

    def _emit_tag_short(self, id, typ, cls):
        """Emit a short (< 31 bytes) tag."""
        assert id < 31
        self._emit(chr(id | typ | cls))

    def _emit_tag_long(self, id, typ, cls):
        """Emit a long (>= 31 bytes) tag."""
        head = chr(typ | cls | 0x1f)
        self._emit(head)
        values = []
        values.append((id & 0x7f))
        id >>= 7
        while id:
            values.append((id & 0x7f) | 0x80)
            id >>= 7
        values.reverse()
        values = map(chr, values)
        for val in values:
            self._emit(val)

    def _emit_length(self, length):
        """Emit length octects."""
        if length < 128:
            self._emit_length_short(length)
        else:
            self._emit_length_long(length)

    def _emit_length_short(self, length):
        """Emit the short length form (< 128 octets)."""
        assert length < 128
        self._emit(chr(length))

    def _emit_length_long(self, length):
        """Emit the long length form (>= 128 octets)."""
        values = []
        while length:
            values.append(length & 0xff)
            length >>= 8
        values.reverse()
        values = map(chr, values)
        # really for correctness as this should not happen anytime soon
        assert len(values) < 127
        head = chr(0x80 | len(values))
        self._emit(head)
        for val in values:
            self._emit(val)

    def _emit(self, s):
        """Emit raw bytes."""
        assert isinstance(s, str)
        self.m_stack[-1].append(s)


class Decoder(object):
    """A ASN.1 decoder. Understands BER (and DER which is a subset)."""

    def __init__(self):
        """Constructor."""
        self.m_stack = None
        self.m_tag = None

    def start(self, data):
        """Start processing `data'."""
        if not isinstance(data, str):
            raise Error, 'Expecting string instance.'
        self.m_stack = [[0, data]]
        self.m_tag = None

    def enter(self):
        """Enter a constructed tag."""
        if self.m_stack is None:
            raise Error, 'No input selected. Call start() first.'
        id, typ, cls = self.peek()
        if typ != TypeConstructed:
            raise Error, 'Cannot enter a non-constructed tag.'
        length = self._read_length()
        bytes = self._read_bytes(length)
        self.m_stack.append([0, bytes])
        self.m_tag = None

    def leave(self):
        """Leave the last entered constructed tag."""
        if self.m_stack is None:
            raise Error, 'No input selected. Call start() first.'
        if len(self.m_stack) == 1:
            raise Error, 'Tag stack is empty.'
        del self.m_stack[-1]
        self.m_tag = None

    def peek(self):
        """Peek the value of the next tag."""
        if self.m_stack is None:
            raise Error, 'No input selected. Call start() first.'
        if self._end_of_input():
            return None
        if self.m_tag is None:
            self.m_tag = self._read_tag()
        return self.m_tag

    def read(self):
        """Read a simple value."""
        if self.m_stack is None:
            raise Error, 'No input selected. Call start() first.'
        if self._end_of_input():
            return None
        tag = self.peek()
        id, typ, cls = tag
        if typ & TypeConstructed:
            raise Error, 'Cannot read a constructed type.'
        length = self._read_length()
        bytes = self._read_bytes(length)
        if id == Boolean:
            value = self._decode_boolean(bytes)
        elif id in (Integer, Enumerated):
            value = self._decode_integer(bytes)
        elif id == OctetString:
            value = self._decode_octet_string(bytes)
        elif id == Null:
            value = self._decode_null(bytes)
        else:
            value = bytes
        self.m_tag = None
        return value

    def _decode_boolean(self, bytes):
        """Decode a boolean value."""
        if len(bytes) != 1:
            raise Error, 'ASN1 syntax error'
        if bytes[0] == '\x00':
            return False
        return True

    def _decode_integer(self, bytes):
        """Decode an integer value."""
        values = [ ord(b) for b in bytes ]
        # check if the integer is normalized
        if len(values) > 1 and \
                (values[0] == 0xff and values[1] & 0x80 or
                 values[0] == 0x00 and not (values[1] & 0x80)):
            raise Error, 'ASN1 syntax error'
        negative = values[0] & 0x80
        if negative:
            # make positive by taking two's complement
            for i in range(len(values)):
                values[i] = 0xff - values[i]
            for i in range(len(values)-1, -1, -1):
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i > 0
                values[i] = 0x00
        value = 0L
        for val in values:
            value = (value << 8) |  val
        if negative:
            value = -value
        try:
            value = int(value)
        except OverflowError:
            pass
        return value

    def _decode_octet_string(self, bytes):
        """Decode an octet string."""
        return bytes

    def _decode_null(self, bytes):
        """Decode a Null value."""
        if len(bytes) != 0:
            raise Error, 'ASN1 syntax error'
        return None

    def _read_tag(self):
        """Read a tag from the input."""
        byte = self._read_byte()
        cls = byte & 0xc0
        typ = byte & 0x20
        id = byte & 0x1f
        if id == 0x1f:
            id = 0
            while True:
                byte = self._read_byte()
                id = (id << 7) | (byte & 0x7f)
                if not byte & 0x80:
                    break
        return (id, typ, cls)

    def _read_length(self):
        """Read a length from the input."""
        byte = self._read_byte()
        if byte & 0x80:
            count = byte & 0x7f
            if count == 0x7f:
                raise Error, 'ASN1 syntax error'
            bytes = self._read_bytes(count)
            bytes = [ ord(b) for b in bytes ]
            length = 0L
            for byte in bytes:
                length = (length << 8) | byte
            try:
                length = int(length)
            except OverflowError:
                pass
        else:
            length = byte
        return length

    def _end_of_input(self):
        """Return True if we are at the end of input."""
        index, input = self.m_stack[-1]
        assert not index > len(input)
        return index == len(input)

    def _read_byte(self):
        """Return the next input byte, or raise an error on end-of-input."""
        index, input = self.m_stack[-1]
        try:
            byte = ord(input[index])
        except IndexError:
            raise Error, 'Premature end of input.'
        self.m_stack[-1][0] += 1
        return byte

    def _read_bytes(self, count):
        """Return the next `count' bytes of input. Raise error on
        end-of-input."""
        index, input = self.m_stack[-1]
        bytes = input[index:index+count]
        if len(bytes) != count:
            raise Error, 'Premature end of input.'
        self.m_stack[-1][0] += count
        return bytes
