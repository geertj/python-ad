#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.system.system import System


class GenericSystem(System):
    """System configuration for a generic system."""

    def detect(self):
        return True

    def isgeneric(self):
        return True

    def nssldap_config_path(self):
        return '/etc/ldap.conf'

    def krb5_config_path(self):
        return '/etc/krb5.conf'

    def systemauth_config_path(self):
        return '/etc/pam.d/system-auth'

    def adclient_config_path(self):
        return '/etc/adclient.conf'

    def openldap_config_path(self):
        return '/etc/openldap/ldap.conf'
