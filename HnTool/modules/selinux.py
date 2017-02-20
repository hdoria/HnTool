# -*- coding: utf-8 -*-
#
# HnTool rules - selinux
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
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

import os
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
        # sestatus, checkpolicy
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
                
                # Checking SELinux policy enforcement
                if 'SELINUX' in lines:
                    if lines['SELINUX'] == 'enforcing':
                        check_results['ok'].append('SELinux is in enforcing mode')
                    elif lines['SELINUX'] == 'permissive':
                        check_results['med'].append('SELinux is in permissive mode')
                    elif lines['SELINUX'] == 'disabled':
                        check_results['high'].append('SELINUX is disabled')
                    else:
                        check_results['high'].append('SELinux policy enforcement is unknown')
                else:
                    check_results['high'].append('SELinux policy enforcement not found')

                # Checking SELinux policy type
                if 'SELINUXTYPE' in lines:
                    if lines['SELINUXTYPE'] == 'mls':
                        check_results['ok'].append('SELinux is using a multi-level security policy')
                    elif lines['SELINUXTYPE'] == 'mcs':
                        check_results['ok'].append('SELinux is using a multi-category security policy')
                    elif lines['SELINUXTYPE'] == 'strict':
                        check_results['ok'].append('SELinux is using a strict security policy')
                    elif lines['SELINUXTYPE'] == 'targeted':
                        check_results['low'].append('SELinux is using a targeted policy')
                    elif lines['SELINUXTYPE'] == 'standard':
                        check_results['med'].append('SELinux is using a standard policy')
                    elif lines['SELINUXTYPE'] == 'minimum':
                        check_results['high'].append('SELinux is using a minimum security policy')
                    else:
                        check_results['high'].append('SELinux policy type is unknown')
                else:
                    check_results['high'].append('SELinux policy type not found')

        return check_results
