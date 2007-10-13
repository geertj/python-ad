#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.

from ctypes import CDLL, Structure, c_int, c_void_p


Krb5Context = c_void_p


class Krb5Creds(Structure):
    pass

class Krb5Principal(Structure):
    pass

class Krb5Data(Structure):
    pass


class Krb5Function(object):

    def __init__(self, func, name=None):
        self.m_func = func
        self.m_name = name

    def __call__(self, *args):
        res = apply(self.m_func, args)
        if res:
            m = 'Kerberos function %s returned error %s' % (self.m_name, res)
            err = KrbError(m)
            err.code = res
            raise err
        return res

class Krb5Library(object):

    c_prototypes = \
    {
        'krb5_init_context': (c_int, [POINTER(c_void_p)]),
        'krb5_get_init_creds_keytab': (c_int,),
        'krb5_get_init_creds_password': (c_int,),
        'krb5_set_password': (c_int, [Krb5Context, POINTER(Krb5Creds), c_char_p,
                              Krb5Principal, POINTER(c_int), POINTER(Krb5Data),
                              POINTER(Krb5Data)]),
        'krb5_change_password': (c_int,)
    }

    def __init__(self):
        self.m_library = None
        self.m_symbols = {}

    def _library():
        if not self.m_library:
            self.m_library = ctypes.CDLL('libkrb5.so')
        return self.m_library

    def _symbol(self, name):
        library = self._library()
        try:
            value = getattr(library, name)
        except AttributeError:
            value = None
        return value

    def __getattr__(self, name):
        if name not in self.m_symbols:
            symbol = self._symbol(name)
            if symbol is None:
                raise AttributeError, name
            if name in self.c_prototypes:
                res, args = self.c_prototypes[name]
                symbol.restype = res
                symbol.argtypes = args
            self.m_symbols = symbol
        return symbol
