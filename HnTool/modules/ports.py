# -*- coding: utf-8 -*-
#
# HnTool rules - port checks
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
import re
from HnTool.modules.rule import Rule as MasterRule

class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name="ports"
        self.long_name="Checks for open ports"
        self.type="config"

    def check_ports(self, lsof_command, check_results):
        ''' Check for open ports and services '''

        out = os.popen('LC_ALL=C ' + lsof_command + ' -i -nP').read()
        services = {}

        # the regex need some improvement
        for i in re.finditer(r'([A-Za-z0-9_-]+).*:([0-9]+) \(LISTEN\)', out):
            service_name = i.group(1)
            service_port = i.group(2)
            if service_name not in services:
                services[service_name] = [service_port]
            elif service_port not in services[service_name]:
                services[service_name].append(service_port)

        if len(services) > 0:
            for service in services:
                if len(services[service]) == 1:
                    tmp_msg = 'port "' + services[service][0] + '"'
                else:
                    tmp_msg = 'ports "' + '" and "'.join(services[service]) \
                            + '"'
                check_results['info'].append('Service "' + service + '" using ' \
                                             + tmp_msg + ' found')
        else:
            check_results['ok'].append("Could not find any open door")

        return check_results

    def analyze(self, options):
        check_results = self.check_results
        lsof_bin_path = ['/bin/lsof', '/sbin/lsof', '/usr/bin/lsof', '/usr/sbin/lsof']

        # checks using lsof
        # checking if we can find the lsof command
        lsof_command = ''
        for lsof in lsof_bin_path:
            if os.path.isfile(lsof):
                lsof_command = lsof
                break

        if len(lsof_command) > 0:
            self.check_ports(lsof_command, check_results)
        else:
            check_results['info'].append('Could not find the \'lsof\' command')

        return check_results