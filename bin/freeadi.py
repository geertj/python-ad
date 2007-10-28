#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import sys
import os.path

from freeadi import ad

def usage():
    """Show a small help text."""
    out = sys.stderr
    progname = os.path.basename(sys.argv[0])
    out.write('Usage: %s <command> [options]\n' % progname)
    out.write('  Valid commands are listed below. Commands marked with an\n')
    out.write('  asterisk (*) require AD administrative access.\n')
    out.write('  * join         join an AD domain (creates computer account) (*)\n')
    out.write('  * retrust      reastablish trust (resets AD and local key) (*)\n')
    out.write('  * set_key      set the local AD key\n')
    out.write('  * schema       implement the AD schema (*)\n')
    out.write('  * refresh      refresh freeadi on this system\n')


def do_refresh(args):
    """Refresh the freeadi configuration on this system."""
    config = get_config()
    hostname = get_hostname()
    domain = get_domain()
    site = ad.detect_side_code()
    if site != config['SITE']:
        config['SITE'] = site
        config.write()
    servers = ad.get_server_list('kerberos')
    servers = ad.filter_server_list(servers, max=5)
    unix.update_krb5_config(servers)
    servers = ad.get_server_list('ldap')
    unix.update_ldap_config(servers)
   
def main():
    """Main function."""
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd == 'join':
        do_join(args)
    elif cmd == 'retrust':
        do_retrust(args)
    elif cmd == 'set_key':
        do_setkey(args)
    elif cmd == 'schema':
        do_schema(args):
    elif cmd == 'refresh':
        do_refresh(args)
