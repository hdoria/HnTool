# -*- coding: utf-8 -*-
#
# HnTool rules - PostgreSQL
# Copyright (C) 2009-2010 Sebastian SWC <mail@sebastianswc.net>
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
import shlex
from HnTool.modules.rule import Rule as MasterRule

class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name="postgresql"
        self.long_name="Check security problems on PostgreSQL configuration files"
        self.type="config"
        self.required_files = ['/var/lib/pgsql/data/pg_hba.conf','/var/lib/pgsql/data/postgresql.conf']

    def requires(self):
        return self.required_files

    def analyze(self, options):
        check_results = self.check_results
        pgsql_conf_file = self.required_files

        for pgsql_conf in pgsql_conf_file:
            if os.path.isfile(pgsql_conf):
                try:
                    fp = open(pgsql_conf,'r')
                except IOError, (errno, strerror):
                    check_results['info'].append('Could not open %s: %s' % (pgsql_conf, strerror))
                    continue

                # pg_hba.conf validation
                if 'pg_hba' in pgsql_conf:
                    for line in fp.readlines():
                        if line[0] != '#' and len(line.strip()) > 0:
                            line_conf = shlex.split(line)

                            # check unix sockets authentication
                            if line_conf[0] == 'local':
                                if 'trust' in line:
                                    check_results['medium'].append('Trusted local Unix authentication are allowed')
                                else:
                                    check_results['ok'].append('Trusted local Unix authentication are not allowed')

                            # check tcp/ip host authentication
                            if 'host' in line_conf[0]:
                                if 'trust' in line:
                                    check_results['high'].append('Trusted connection on ' + line_conf[3] + ' are allowed')
                                else:
                                    check_results['ok'].append('Trusted connection on ' + line_conf[3] + ' are not allowed')

                elif 'postgresql' in pgsql_conf:
                    for line in fp.readlines():
                        if len(line.strip()) > 0:
                            line_conf = shlex.split(line)

                            # check the default port
                            if 'port =' in line:
                                if '5432' in line:
                                    check_results['low'].append('Server are running on default port (5432)')
                                else:
                                    check_results['ok'].append('Server are not running at default port (5432)')
                            # check sshl connections
                            if 'ssl =' in line:
                                if 'off' in line:
                                    check_results['low'].append('Server are running without ssl connections support')
                                else:
                                    check_results['ok'].append('Server are running with ssl connections support')
                fp.close()

        return check_results