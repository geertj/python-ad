#
# This file is part of FreeADI. FreeADI is free software and is made available
# under the terms of the GNU General Public License, version 3. Consult the
# file "LICENSE" that is distributed together with this file for the exact
# licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file "AUTHORS"
# for a complete overview.


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
