#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.


def decompress(buffer, offset, _pointer=False):
    """Decompress an RFC1035 (section 4.1.4) compressed string."""
    result = []
    while True:
        if offset >= len(buffer):
            raise ValueError, 'Premature end of message'
        tag = ord(buffer[offset])
        offset += 1
        if tag == 0:
            break
        elif tag & 0xc0 == 0xc0:
            if _pointer:
                raise ValueError, 'Recursive pointer'
            if offset >= len(buffer):
                raise ValueError, 'Premature end of message'
            ptr = ((tag & ~0xc0) << 8) + ord(buffer[offset])
            offset += 1
            result.append(decompress(buffer, ptr, True)[0])
            break
        elif tag & 0xc0:
            raise ValueError, 'Illegal tag'
        else:
            if offset+tag >= len(buffer):
                raise ValueError, 'Premature end of message'
            s = buffer[offset:offset+tag]
            result.append(s)
            offset += tag
    result = '.'.join(result)
    return result, offset
