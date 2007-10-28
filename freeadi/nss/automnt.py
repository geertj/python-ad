#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from ctypes import Structure, byref, c_char_p, c_void_p


class Automnt(Structure):
    """One entry from the automount naming service."""

    _fields_ = [('key', c_char_p),
                ('value', c_char_p)]

    def __str__(self):
        return '%s %s' % (self.key, self.value)


class AutomntNamingService(NamingService):
    """The automount naming service.

    This provides for automount enumeration on a single naming service module.
    """

    result_type = Automnt

    def __init__(self):
        """Constructor."""
        super(AutomntNamingService, self).__init__()
        self._load_functions()

    def _load_functions(self):
        """Load functions from the dll."""
        func = self._get_symbol('setautomntent')
        func.argtypes = [c_char_p, POINTER(c_void_p)]
        func.restype = [c_int]
        self._setautomntent = func
        func = self._get_symbol('getautomntent_r')
        func.argtypes = [c_void_p, POINTER(c_char_p), POINTER(c_char_p),
                         c_char_p, c_int, POINTER(c_int)]
        func.restype = [c_int]
        self._getautomntent_r = func
        func = self._get_symbol('endautomntent')
        func.argtypes = [POINTER(c_void_p)]
        func.restype = [c_int]
        self._endautomntent = func
 
    def set_map(self, mapname):
        """Set the map to enumerate over to `mapname'."""
        self.m_mapname = mapname

    def _setent(self):
        """Start enumeration."""
        self.m_private = c_void_p();
        self._setautomntent(self.m_mapname, byref(self.m_private))

    def _getent(self, result, buffer, buflen, errno):
        """Get one entry."""
        key = ctypes.c_char_p();
        value = ctypes.c_char_p();
        res = self._getautomntent(self.m_private, byref(key), byref(value),
                                  buffer, buflen, errno)
        result.key = key
        result.value = value
        return res

    def _endent(self):
        """End enumeration."""
        self._endautomntent(byref(self.m_private))
