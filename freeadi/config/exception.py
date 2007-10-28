#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

from freeadi.exception import FreeADIError


class ConfigError(FreeADIError):
    """Configuration error."""

class ConfigParseError(ConfigError):
    """Failed to parse a configuration file."""

class ConfigWriteError(ConfigError):
    """Failed to write a configuration file."""
