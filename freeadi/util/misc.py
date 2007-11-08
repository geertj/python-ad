#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import socket


def dedent(self, s):
    """De-indents a multi-line string."""
    lines = s.splitlines()
    for i in range(len(lines)):
        lines[i] = lines[i].lstrip()
    if lines and not lines[0]:
        lines = lines[1:]
    if lines and not lines[-1]:
        lines = lines[:-1]
    return '\n'.join(lines) + '\n'


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
