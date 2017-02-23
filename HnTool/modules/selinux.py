# -*- coding: utf-8 -*-
#
# HnTool rules - selinux
# Copyright (C) 2017 Dan Persons <dpersonsdev@gmail.com>
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
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

import os
import re
import shlex
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule

class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name="selinux"
        self.long_name="Checks SELinux configuration"
        self.type="config"
        self.required_files = ['/etc/selinux/config']
        # TO DO: add try/except to get live config settings
        # sestatus, checklive
        # Compare to configured settings

    def requires(self):
        return self.required_files

    def analyze(self, options):
        check_results = self.check_results
        selinux_conf_file = self.required_files

        for selinux_conf in selinux_conf_file:
            if os.path.isfile(selinux_conf):
                # dict with all the lines
                lines = HnTool.modules.util.hntool_conf_parser_equals(selinux_conf)
                
                # Checking SELinux policy enforcement config
                if 'SELINUX' in lines:
                    if lines['SELINUX'] == 'enforcing':
                        check_results['ok'].append('Configured in enforcing mode')
                    elif lines['SELINUX'] == 'permissive':
                        check_results['med'].append('Configured in permissive mode')
                    elif lines['SELINUX'] == 'disabled':
                        check_results['high'].append('Configured as disabled')
                    else:
                        check_results['high'].append('Policy enforcement unknown')
                else:
                    check_results['high'].append('Policy enforcement not found')

                # Checking SELinux policy type config
                if 'SELINUXTYPE' in lines:
                    if lines['SELINUXTYPE'] == 'mls':
                        check_results['ok'].append('Configured using a multi-level security policy')
                    elif lines['SELINUXTYPE'] == 'mcs':
                        check_results['ok'].append('Configured using a multi-category security policy')
                    elif lines['SELINUXTYPE'] == 'strict':
                        check_results['ok'].append('Configured using a strict security policy')
                    elif lines['SELINUXTYPE'] == 'targeted':
                        check_results['low'].append('Configured using a targeted policy')
                    elif lines['SELINUXTYPE'] == 'standard':
                        check_results['med'].append('Configured using a standard policy')
                    elif lines['SELINUXTYPE'] == 'minimum':
                        check_results['high'].append('Configured using a minimum security policy')
                    else:
                        check_results['high'].append('SELinux policy type is unknown')
                else:
                    check_results['high'].append('SELinux policy type not found')

            # To Do: add check to make sure live env matches config
            liveconfig = os.popen('sestatus').readlines()
            optionformat = re.compile('(.*):')
            checklive = {}

            for item in liveconfig:
                thing = item.rstrip()
                itemname = re.findall(optionformat, thing)
                itemval = shlex.split(thing)[-1]
                # itemval = thing.split(':')[-1].rstrip()
                checklive[itemname[0]] = itemval

            if 'bash' in checklive:
                if 'SELINUX' in lines:
                    check_results['high'].append('SELinux: sestatus command not found')
            if 'sestatus' in checklive:
                if 'SELINUX' in lines:
                    check_results['high'].append('SELinux: sestatus command not found')

            if 'SELinux status' in checklive:
                if checklive['SELinux status'] == 'enabled':
                        check_results['ok'].append('SELinux is enabled')
                elif checklive[-1] == 'disabled' and \
                        lines['SELINUX'] != 'disabled':
                    check_results['high'].append('SELinux is disabled but should be on')
                else:
                    check_results['high'].append('SELinux is disabled')

            if 'Current mode' and 'Mode from config file' in checklive:
                if checklive['Current mode'] and checklive['Mode from config file'] == lines['SELINUX']:
                    check_results['ok'].append('Enforcement running as configured')
                else:
                    check_results['high'].append('Enforcement not running as configured')
    
            if 'Loaded policy name' in checklive:
                if checklive['Loaded policy name'] == lines['SELINUXTYPE']:
                    check_results['ok'].append('Policy type running as configured')
                else:
                    check_results['high'].append('Policy type not running as configured')

            if 'Policy MLS status' in checklive:
                if checklive['Policy MLS status'] == 'enabled':
                    check_results['ok'].append('Policy MLS status enabled')
                else:
                    check_results['low'].append('Policy MLS status disabled')

            if 'Policy deny_unknown status' in checklive:
                if checklive['Policy deny_unknown status'] == 'denied':
                    check_results['ok'].append('Policy deny_unkown status set to denied')
                else:
                    check_results['low'].append('Policy deny_unknown status set to allowed')

        return check_results
