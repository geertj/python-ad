#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.exception import FreeADIError


class System(object):
    """System configuration base class.

    This class defines the API for system configuration classes. The
    API is used to retrieve system specific configuration items such
    as configuration file locations.

    It class also defines factory function that returns the best match
    for the current system.
    """

    @classmethod
    def _load_system(cls, name):
        exec 'import from freeadi.system import %s as module' % name
        for sym in dir(module):
            obj = getattr(module, sym)
            if issubclass(obj, cls):
                return obj
        else:
            m = 'No system class found in freeadi.system.%s' % name
            raise FreeADIError, m

    @classmethod
    def factory(cls):
        """Creates a System instance for the current system."""
        systems = ['generic']
        for sys in systems:
            obj = cls._load_system(cls)()
            if obj.detect():
                return obj
        else:
            assert False, 'The generic system class did not match.'

    def detect(self):
        """Return True if the current system class matches."""
        raise NotImplementedError

    def isgeneric(self):
        """Return True if this is the generic system configuration."""
        raise NotImplementedError

    def nssldap_config_path(self):
        """Return the path of the nssldap configuration file."""
        raise NotImplementedError

    def krb5_config_path(self):
        """Return the path of the Kerberos configuration file."""
        raise NotImplementedError
 
    def systemauth_config_path(self):
        """Return the path of the system-auth PAM configuration file."""
        raise NotImplementedError

    def adclient_config_path(self):
        """Return the path of the ad client configuration file."""
        raise NotImplementedError

    def openldap_config_path(self):
        """Return the path of the OpenLDAP configuration file."""
        raise NotImplementedError
