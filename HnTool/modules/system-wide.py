# -*- coding: utf-8 -*-
#
# HnTool rules - system-wide
# Copyright (C) 2009-2010 Hugo Doria <mail@hugodoria.org>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import os
import stat
from HnTool.modules.rule import Rule as MasterRule

class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name="system-wide"
        self.long_name="Checks security problems on system-wide configuration"
        self.type="config"

    def analyze(self, options):
        check_results = self.check_results
        grub_conf_file = ['/boot/grub/menu.lst']
        inittab_file = ['/etc/inittab']
        sysctl_conf_file = ['/etc/sysctl.conf']

        # Checking GRUB configuration file
        for grub_conf in grub_conf_file:
            if os.path.isfile(grub_conf):
                try:
                    fp = open(grub_conf,'r')
                except IOError, (errno, strerror):
                    check_results[4].append('Could not open %s: %s' % (grub_conf, strerror))
                    continue

                grub_conf_lines = [x.strip('\n') for x in fp.readlines()]

                # Getting only the line that starts with password
                password_lines = [x for x in grub_conf_lines if x.startswith('password')]

                # Checking if grub is asking for a password
                # if password_lines size is more than 0 then there's a line
                # starting with 'passwd' on our grub config file
                if len(password_lines) > 0:
                    check_results['ok'].append('GRUB asks for a password')
                else:
                    check_results['low'].append('GRUB does not ask for a password')

                # Closing the grub_conf file
                fp.close()

                # Checking grub_conf permissions
                if oct(os.stat(grub_conf)[stat.ST_MODE] & 0777) == oct(0600):
                    check_results['ok'].append('Permissions on ' + grub_conf +
                                               ' are correct')
                elif oct(os.stat(grub_conf)[stat.ST_MODE] & 0777) > oct(0600):
                    check_results['low'].append('Permissions on ' + grub_conf +
                                                ' are greater than 600')

        # Checking inittab file
        for inittab in inittab_file:
            if os.path.isfile(inittab):
                try:
                    fp = open(inittab, 'r') # open the inittab file
                except IOError, (errno, strerror):
                    check_results[4].append('Could not open %s: %s' % (inittab, strerror))
                    continue

                # Getting the lines from the inititab file
                inittab_lines = [x.strip('\n') for x in fp.readlines()]

                if 'su:S:wait:/sbin/sulogin' in inittab_lines:
                    check_results['ok'].append('Single-User mode requires' +
                                               ' authentication')
                else:
                    check_results['medium'].append('Single-User mode does not' +
                                                   ' requires authentication')

                # Closing the inititab file
                fp.close()

        # Checking sysctl.conf file
        for sysctl in sysctl_conf_file:
            if os.path.isfile(sysctl):
                try:
                    fp = open(sysctl, 'r') # open the sysctl.conf file
                except IOError, (errno, strerror):
                    check_results[4].append('Could not open %s: %s' % (sysctl, strerror))
                    continue

                # Getting the lines from the sysctl configuration file
                # We need to strip all white spaces and \n for each line
                # This way we don't need to worry if the user is using
                # var = 1 (with spaces) or var=1 (w/o spaces) in sysctl.conf
                sysctl_lines = [x.strip('\n').replace(' ', '') for x in fp.readlines()]

                # Checking if core dumps are enabled
                # disabled is good
                if 'fs.suid_dumpable=0' in sysctl_lines:
                    check_results['ok'].append('Core dumps are disabled')
                else:
                    check_results['low'].append('Core dumps are enabled')

                # Checking if exec shield is enabled
                # enabled is good
                if ('kernel.exec-shield=1' and 'kernel.randomize_va_space=1') in sysctl_lines:
                    check_results['ok'].append('ExecShield is enabled')
                else:
                    check_results['low'].append('ExecShield is disabled')

                # Checking if TCP SYN Cookie Protection is enabled
                # enabled is good
                if 'net.ipv4.tcp_syncookies=1' in sysctl_lines:
                    check_results['ok'].append('TCP SYN Cookie Protection is enabled')
                else:
                    check_results['low'].append('TCP SYN Cookie Protection is disabled')

                # Checking if we are ignoring broadcast requests
                # enabled is good
                if 'net.ipv4.icmp_echo_ignore_broadcasts=1' in sysctl_lines:
                    check_results['ok'].append('Ignore broadcast request is enabled')
                else:
                    check_results['low'].append('Ignore broadcast request is disabled')

                # Checking if Ping Reply is disabled
                # disabled is good
                if 'net.ipv4.icmp_echo_ignore_all=1' in sysctl_lines:
                    check_results['ok'].append('Ping reply is disabled')
                else:
                    check_results['low'].append('Ping reply is enabled')

                # Closing the sysctl file
                fp.close()

        return check_results