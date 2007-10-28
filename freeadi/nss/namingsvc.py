#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from ctypes import CDLL, create_string_buffer, byref, c_int
from freeadi.nss.exception import NssError


class NamingService(object):
    """Naming Service.

    This object provides for enumeration for a naming service using
    a single NSS module.
    """

    # NSS status codes from nss.h
    NSS_STATUS_TRYAGAIN = -2
    NSS_STATUS_UNAVAIL = -1
    NSS_STATUS_NOTFOUND = 0
    NSS_STATUS_SUCCESS = 1
    NSS_STATUS_RETURN = 2

    def __init__(self, service):
        """Constructor."""
        self.m_service = service
        self.m_module = self._load_module()

    def _load_module(self):
        """Load the naming service module."""
        mname = 'libnss_%s.so' % self.m_service
        module = CDLL(mname)
        return module

    def _get_symbol(self, name):
        """Load a symbol from the naming service module."""
        name = '_nss_%s_%s' % (self.m_service, name)
        func = getattr(self.m_module, name)
        return func

    def __iter__(self):
        """Iterator."""
        self._setent()
        result = self.result_type()
        size = 1024
        buffer = create_string_buffer(size)
        errno = c_int()
        while True:
            res = self._getent(byref(result), buffer, size, byref(errno))
            if res == self.NSS_STATUS_TRYAGAIN:
                size *= 2
                buffer = create_string_buffer(size)
            elif res == self.NSS_STATUS_SUCCESS:
                yield result
            elif res == self.NSS_STATUS_NOTFOUND:
                self._endent()
                raise StopIteration
            else:
                m = 'NSS status ds in enumeration (errno = %d)' % \
                    (res, errno.value)
                raise NssError, m
