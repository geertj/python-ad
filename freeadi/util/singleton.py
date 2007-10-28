#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.


def singleton(cls, *args, **kwargs):
    """Return the current instance of this class.
    
    This method assumes a factory method named 'factory' is present on the
    object and will use that to create the first instance.
    """
    if not hasattr(cls, 'c_instance') or cls.c_instance is None:
        obj = apply(cls.factory, args, kwargs)
        cls.c_instance = obj
    return cls.c_instance
