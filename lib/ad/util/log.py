#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007-2009 by the Python-AD authors. See the
# file "AUTHORS" for a complete overview.

import sys
import logging


def enable_logging(level=None):
    """Utility function to enable logging for the "ad" package if no root
    logger is configured yet."""
    if level is None:
        level = logging.DEBUG
    logger = logging.getLogger('ad')
    handler = logging.StreamHandler(sys.stdout)
    format = '%(levelname)s [%(name)s] %(message)s'
    formatter = logging.Formatter(format)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
