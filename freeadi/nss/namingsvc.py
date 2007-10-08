#
# This file is part of freeadi. Freeadi is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# Freeadi is copyright (c) 2007 by the freeadi authors. See the file "AUTHORS"
# for a complete overview.

from ctypes import CDLL


class NamingService(object):
    """Naming Service.

    This object provides for enumeration for a naming service using
    a single NSS module.
    """

    NSS_STATUS_TRYAGAIN = -2
    NSS_STATUS_UNAVAIL = -1
    NSS_STATUS_NOTFOUND = 0
    NSS_STATUS_SUCCESS = 1
    NSS_STATUS_RETURN = 2

    def __init__(self, service):
        self.m_service = service
        self.m_module = self._load_module()

    def _load_module(self):
        mname = 'libnss_%s.so' % self.m_service
        module = CDLL(mname)
        return module

    def _get_symbol(self, name):
        name = '_nss_%s_%s' % (self.m_service, name)
        func = getattr(self.m_module, name)
        return func

    def __iter__(self):
        return self

    def next(self):
        self._setent()
        res = self.type()
        size = 1024
        buffer = create_string_buffer(size)
        errno = c_int()
        while True:
            res = getpwent(byref(res), buffer, size, byref(errno))
            if res == NSS_STATUS_TRYAGAIN:
                size *= 2
                buffer = create_string_buffer(size)
            elif res == NSS_STATUS_SUCCESS:
                yield res
            elif res == NSS_STATUS_NOTFOUND:
                self._endent()
                raise StopIteration
            else:
                raise NssError
