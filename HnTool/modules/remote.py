# -*- coding: utf-8 -*-
#
# HnTool rules - remote access
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
from HnTool.modules.rule import Rule as MasterRule

class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name="remote_access"
        self.long_name="Checks for services with remote access allowed"
        self.type="config"

    def analyze(self, options):
        check_results = self.check_results
        hosts_allow_file = '/etc/hosts.allow'
        hosts_deny_file  = '/etc/hosts.deny'

        # Checks about the hosts.deny file
        if os.path.isfile(hosts_deny_file):
            fp = open(hosts_deny_file, 'r') #open file
            # getting all the lines from the file
            lines = [x.strip('\n').split(':') for x in fp.readlines()]

            # getting all the lines that are not comments or blanks
            all_access = [x for i, x in enumerate(lines) \
                          if not (x[0].startswith('#') or not x[0] != '')]

            for indexc, line in enumerate(all_access):
                for indexv, col in enumerate(line):
                    all_access[indexc][indexv] = col.strip()

            if all_access:
                for index, service in enumerate(all_access):

                    # if len(service) >= 3 then the file is using 3 parameters
                    if len(service) == 3:
                        #specific service with all access
                        if (service[0] == 'ALL' and \
                            service[1] == 'ALL' and \
                            service[2] == 'DENY'):
                            check_results['ok'].append("By default, services are rejecting connections")

                    # if len(service) == 2 then the file is using 2 parameters
                    elif len(service) == 2:
                        #specific service with all access
                        if (service[0] == 'ALL' and \
                            service[1] == 'ALL'):
                            check_results['ok'].append("By default, services are rejecting connections")
            else:
                check_results['low'].append('Default policy not found')

            #closing file
            fp.close()


        # Checks about the hosts.allow file
        if os.path.isfile(hosts_allow_file):
            fp = open(hosts_allow_file,'r')
            all_access = [x.strip('\n').split(':') for x in fp.readlines()]

            #check access in hosts.allow and remove comments and whitespaces
            all_access = [x for i,x in enumerate(all_access) \
                          if not (x[0].startswith('#') or not (x[0] != ''))]
            for indexc, line in enumerate(all_access):
                for indexv, col in enumerate(line):
                    all_access[indexc][indexv] = col.strip()

            if all_access:
                for index, service in enumerate(all_access):
                    #specific service with all access
                    if service[0] != 'ALL' and service[1] == 'ALL':
                        check_results['medium'].append('Service "' + service[0] + \
                                                       '" accepts remote connections from ALL')
                    #specific service with all access
                    elif service[0] != 'ALL' and service[1] != 'ALL':
                        check_results['medium'].append('Service "' + service[0] + \
                                                       '" accepts remote connections from "' + service[1] + '"')
                    #any service to specific address
                    elif service[0] == 'ALL' and service[1] != 'ALL':
                        check_results['medium'].append('Services are accepting remote access from "' + service[1] + '"')
                    #any service with all access
                    elif service[0] == 'ALL' and service[1] == 'ALL':
                        check_results['high'].append('Services are accepting remote access from ALL')
            #closing file
            fp.close()
        else:
            check_results['ok'].append("There's no service accepting remote connections from ALL")

        return check_results