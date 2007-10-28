#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.util.singleton import singleton


class MyClass(object):

    def __init__(self, args, kwargs):
        self.args = args
        self.kwargs = kwargs

    def factory(cls, *args, **kwargs):
        return cls(args, kwargs)

    factory = classmethod(factory)


class TestSingleton(object):
    """Test suite for singleton."""

    def setup_method(cls, method):
        MyClass.c_instance = None

    def test_simple(self):
        ob1 = singleton(MyClass)
        ob2 = singleton(MyClass)
        assert ob1 is ob2

    def test_args(self):
        ob = singleton(MyClass, 10, 20)
        assert ob.args == (10, 20)

    def test_kwargs(self):
        ob = singleton(MyClass, arg1=10, arg2=20)
        assert ob.kwargs == { 'arg1': 10, 'arg2': 20  }

    def test_full_args(self):
        ob = singleton(MyClass, 10, 20, arg1=30, arg2=40)
        assert ob.args == (10, 20)
        assert ob.kwargs == { 'arg1': 30, 'arg2': 40  }
