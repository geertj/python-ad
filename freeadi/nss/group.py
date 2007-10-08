#
# This file is part of freeadi. Freeadi is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# Freeadi is copyright (c) 2007 by the freeadi authors. See the file "AUTHORS"
# for a complete overview.

from ctypes import Structure, POINTER, c_char_p, c_int
from freeadi.nss.namingsvc import NamingService


class Group(Structure):
    """One entry from the group file."""

    _fields_ = [('gr_name', c_char_p),
                ('gr_passwd', c_char_p),
                ('gr_gid', c_int),
                ('gr_mem', POINTER(c_char_p))]

    def __str__(self):
        members = []
        i = 0
        while self.gr_mem[i] != None:
            members.append(self.gr_mem[i])
            i += 1
        members = ','.join(members)
        return '%s:%s:%d:%s' % (self.gr_name, self.gr_passwd, self.gr_gid,
                                members)


class GroupNamingService(NamingService):
    """The group naming service.

    This object provides an iterator over the Unix "group" database for a
    specific naming service.
    """

    result_type = Group

    def __init__(self, service):
        """Constructor."""
        super(GroupNamingService, self).__init__(service)
        self._load_functions()

    def _load_functions(self):
        """Load functions from the dll."""
        func = self._get_symbol('setgrent')
        func.argtypes = []
        func.restype = c_int
        self._setgrent = func
        func = self._get_symbol('getgrent_r')
        func.argtypes = [POINTER(Group), c_char_p, c_int, POINTER(c_int)]
        func.restype = c_int
        self._getgrent_r = func
        func = self._get_symbol('endgrent')
        func.argtypes = []
        func.restype = c_int
        self._endgrent = func

    def _setent(self):
        """Start enumeration."""
        return self._setgrent()

    def _getent(self, result, buffer, size, errno):
        """Return the next entry."""
        return self._getgrent_r(result, buffer, size, errno)

    def _endent(self):
        """Finalize the enumeration."""
        return self._endgrent()
