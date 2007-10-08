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


class Passwd(Structure):
    """One entry from the passwd naming service."""

    _fields_ = [('pw_name', c_char_p),
                ('pw_passwd', c_char_p),
                ('pw_uid', c_int),
                ('pw_gid', c_int),
                ('pw_gecos', c_char_p),
                ('pw_dir', c_char_p),
                ('pw_shell', c_char_p)]

    def __str__(self):
        return '%s:%s:%d:%d:%s:%s:%s' % \
                    (self.pw_name, self.pw_passwd, self.pw_uid, self.pw_gid,
                     self.pw_gecos, self.pw_dir, self.pw_shell)


class PasswdNamingService(NamingService):
    """The passwd naming service.

    This object provides an iterator over the Unix "passwd" naming service
    from a specific NSS module.
    """

    result_type = Passwd

    def __init__(self, service):
        """Constructor."""
        super(PasswdNamingService, self).__init__(service)
        self._load_functions()

    def _load_functions(self):
        """Load functions from the dll."""
        func = self._get_symbol('setpwent')
        func.argtypes = []
        func.restype = c_int
        self._setpwent = func
        func = self._get_symbol('getpwent_r')
        func.argtypes = [POINTER(Passwd), c_char_p, c_int, POINTER(c_int)]
        func.restype = c_int
        self._getpwent_r = func
        func = self._get_symbol('endpwent')
        func.argtypes = []
        func.restype = c_int
        self._endpwent = func

    def _setent(self):
        """Start enumeration."""
        return self._setpwent()

    def _getent(self, result, buffer, size, errno):
        """Return the next entry."""
        return self._getpwent_r(result, buffer, size, errno)
        
    def _endent(self):
        """Finalize the enumeration."""
        return self._endpwent()
