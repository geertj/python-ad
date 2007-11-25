#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

import socket


def hostname():
    """Return the host name.

    The host name is defined as the "short" host name. If the hostname as
    returned by gethostname() includes a domain, the part until the first
    period ('.') is returned.
    """
    hostname = socket.gethostname()
    if '.' in hostname:
        hostname = hostname.split('.')[0]
    return hostname
