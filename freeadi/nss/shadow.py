#
# This file is part of freeadi. Freeadi is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# Freeadi is copyright (c) 2007 by the freeadi authors. See the file "AUTHORS"
# for a complete overview.

from ctypes import Structure, POINTER, c_char_p, c_int, c_long, c_ulong
from freeadi.nss.namingsvc import NamingService


class Spwd(Structure):
    """One entry from the shadow naming service."""

    _fields_ = [('sp_namp', c_char_p),
                ('sp_pwdp', c_char_p),
                ('sp_lstchg', c_long),
                ('sp_min', c_long),
                ('sp_max', c_long),
                ('sp_warn', c_long),
                ('sp_inact', c_long),
                ('sp_expire', c_long),
                ('sp_flag', c_long)]

    def __str__(self):
        return '%s:%s:%d:%d:%d:%d:%d:%d:%d' % \
                    (self.sp_namp, self.sp_pwdp, self.sp_lstchg, self.sp_min,
                     self.sp_max, self.sp_warn, self.sp_inact, self.sp_expire,
                     self.sp_flag)


class ShadowNamingService(NamingService):
    """The shadow naming service.

    This object provides an iterator over the Unix "shadow" naming service
    from a specific NSS module.
    """

    result_type = Spwd

    def __init__(self, service):
        """Constructor."""
        super(ShadowNamingService, self).__init__(service)
        self._load_functions()

    def _load_functions(self):
        """Load functions from the dll."""
        func = self._get_symbol('setspent')
        func.argtypes = []
        func.restype = c_int
        self._setspent = func
        func = self._get_symbol('getspent_r')
        func.argtypes = [POINTER(Spwd), c_char_p, c_int, POINTER(c_int)]
        func.restype = c_int
        self._getspent_r = func
        func = self._get_symbol('endspent')
        func.argtypes = []
        func.restype = c_int
        self._endspent = func

    def _setent(self):
        """Start enumeration."""
        return self._setspent()

    def _getent(self, result, buffer, size, errno):
        """Return the next entry."""
        return self._getspent_r(result, buffer, size, errno)

    def _endent(self):
        """Finalize the enumeration."""
        return self._endspent()
