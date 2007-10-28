#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

class Singleton(object):
    """Base class for singleton objects."""

    c_instance = None

    def instance(cls, *args, **kwargs):
        """Return the current instance of this class."""
        if cls.c_instance is None:
            obj = apply(cls.factory, args, kwargs)
            cls.c_instance = obj
        return cls.c_instance

    instance = classmethod(instance)
