#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.


def _singleton(cls, *args, **kwargs):
    """Return the single instance of a class, creating it if it does not exist."""
    if not hasattr(cls, 'instance') or cls.instance is None:
        obj = apply(cls, args, kwargs)
        cls.instance = obj
    return cls.instance

def instance(cls):
    """Return the single instance of a class. The instance needs to exist."""
    if not hasattr(cls, 'instance'):
        raise RuntimeError, 'No instance available for %s' % cls
    return cls.instance

def factory(cls):
    """Create an instance of a class, creating it using the system specific
    rules."""
    from freeadi.core.locate import Locator
    from freeadi.core.creds import Creds
    if issubclass(cls, Locator):
        return _singleton(Locator)
    elif issubclass(cls, Creds):
        domain = detect_domain()
        return Creds(domain)
    else:
        return cls()

def activate(obj):
    """Activate `obj' to be the active instance of its class."""
    from freeadi.core.creds import Creds
    if isinstance(obj, Creds):
        obj._activate_config()
        obj._activate_ccache()
    type(obj).instance = obj
    return obj
