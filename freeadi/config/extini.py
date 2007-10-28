#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from parse_extini import ExtIniParser
from write_extini import ExtIniWriter
from config import Config


class ExtIniConfig(Config):
    """Extended INI file configuration file."""

    def __init__(self):
        super(ExtIniConfig, self).__init__(ExtIniParser, ExtIniWriter)
