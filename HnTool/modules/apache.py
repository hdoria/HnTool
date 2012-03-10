# -*- coding: utf-8 -*-
#
# HnTool rules - apache
# Copyright (C) 2009-2010 Rafael Gomes <rafaelgomes@techfree.com.br>
#		2010 Elton Pereira <eltonplima@gmail.com>
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

# To do : Include code to check when sintax that there isn't in conf

import os
import commands
import stat
from HnTool.modules.rule import Rule as MasterRule

class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name="apache"
        self.long_name="Checks security problems on Apache config file"
        self.type="config"
        self.required_files = ['/etc/httpd/conf/httpd.conf',
                           '/etc/apache2/conf.d/security',
                           '/etc/apache2/apache2.conf']

        options.add_option(
            '--apache_conf',
            action='append',
            dest='apache_conf',
            help='adds a apache configuration file to the list of files to' +
            ' analize'
        )

    def requires(self):
        return self.required_files

    def analyze(self, options):
        """ Analyze Apache config file searching for harmful settings"""

        check_results = self.check_results
        apache_conf_files = self.required_files

        if options.apache_conf:
            for f in options.apache_conf:
                apache_conf_files.append(f)

        apache_conf_file_found = False
        for apache_conf in apache_conf_files:
            if os.path.isfile(apache_conf):
                apache_conf_file_found = True
                fp = None

                try:
                    fp = open(apache_conf, 'r')
                except IOError, (errno, strerror):
                    check_results['info'].append(
                        'Could not open %s: %s' % (apache_conf, strerror)
                    )
                    continue

                lines = [x.strip('\n') for x in fp.readlines()]
                fp.close()

                # Checking if ServerTokens is using harmful conf
                if not 'ServerTokens Minimal' in lines:
                    check_results['ok'].append(
                        'ServerTokens is not using harmful conf'
                    )
                else:
                    check_results['medium'].append(
                        'ServerTokens is using harmful conf (set Minimal)'
                    )

                # Checking if KeepAlive is set to On
                if 'KeepAlive On' in lines:
                    check_results['ok'].append(
                        'KeepAlive is not using harmful conf'
                    )
                else:
                    check_results['medium'].append(
                        'KeepAlive is using harmful conf (set On)'
                    )

                # Checking if ServerSignature is set to On
                if 'ServerSignature Off' in lines:
                    check_results['ok'].append(
                        'ServerSignature is not using harmful conf'
                    )
                else:
                    check_results['medium'].append(
                        'ServerSignature is using harmful conf (set Off)'
                    )

                # Checking if LimitRequestBody is bigger than 0
                if 'LimitRequestBody' in lines:
                    for line in lines:
                        if line.startswith('LimitRequestBody') is True:
                            piece = line.split(' ')
                            if int(piece[1]) == 0:
                                check_results['ok'].append(
                                    'LimitRequestBody is not using harmful' +
                                    ' value (0)'
                                )
                            else:
                                check_results['medium'].append(
                                    'LimitRequestBody is using harmful value' +
                                    ' (0)'
                                )
                else:
                    check_results['ok'].append(
                        'LimitRequestBody is not using harmful value (0)'
                    )

                # Checking if LimitRequestFields is bigger than 0
                if 'LimitRequestFields' in lines:
                    for line in lines:
                        if line.startswith('LimitRequestFields') is True:
                            piece = line.split(' ')
                            if int(piece[1]) == 0:
                                check_results['ok'].append(
                                    'LimitRequestFields is not using harmful' +
                                    ' value (0)'
                                )
                            else:
                                check_results['medium'].append(
                                    'LimitRequestFields is using harmful' +
                                    ' value (0)'
                                )
                else:
                    check_results['ok'].append(
                        'LimitRequestFields is not using harmful value (0)'
                    )

                # Checking if LimitRequestFieldsize is equal 8190
                if 'LimitRequestFieldsize' in lines:
                    for line in lines:
                        if line.startswith('LimitRequestFieldsize') is True:
                            piece = line.split(' ')
                            if int(piece[1]) == 0:
                                check_results['ok'].append(
                                    'LimitRequestFieldsize is using good' +
                                    ' value (8190)'
                                )
                            else:
                                check_results['low'].append(
                                    'LimitRequestFieldsize is not using good' +
                                    ' value (8190)'
                                )
                else:
                    check_results['ok'].append(
                        'LimitRequestFieldsize is using good value (8190)'
                    )

                # Checking if LimitRequestLine is equal 8190
                if 'LimitRequestLine' in lines:
                    for line in lines:
                        if line.startswith('LimitRequestLine') is True:
                            piece = line.split(' ')
                            if int(piece[1]) == 0:
                                check_results['ok'].append(
                                    'LimitRequestLine is using good value' +
                                    ' (8190)'
                                )
                            else:
                                check_results['low'].append(
                                    'LimitRequestLine is not using good' +
                                    ' value (8190)'
                                )
                else:
                    check_results['ok'].append(
                        'LimitRequestLine is using good value (8190)'
                    )

                # Checking Timeout less than 300
                tvalue = 300
                for line in lines:
                    if line.startswith('Timeout') is True:
                        piece = line.split(' ')
                        if int(piece[1]) <= tvalue:
                            check_results['ok'].append(
                                'Timeout is not using harmful value (>=%s)'
                                % (tvalue)
                            )
                        else:
                            check_results['medium'].append(
                                'Timeout is using harmful value (>=%s)'
                                % (tvalue)
                            )

                # Checking if access to Apache manual is enabled
                for line in lines:
                    if line.startswith('Alias /manual/') is True:
                        piece = line.split(' ')
                        if (piece[1]) == '/manual/':
                            check_results['medium'].append(
                                'Access to Apache manual is enabled'
                            )
                        else:
                            check_results['ok'].append(
                                'Access to Apache manual is disabled'
                            )

        # Checking .htpasswd files permission
        mode = "550"
        mode = int(mode, 8)
        locate_status, locate_returns = \
                     commands.getstatusoutput('locate .htpasswd')

        if os.path.exists(locate_returns):
            if locate_status == 0:
                for locate_return in locate_returns.split('\n'):
                    if stat.S_IMODE(os.stat(locate_return).st_mode) == mode:
                        check_results['ok'].append(
                            'The file %s is not using harmful permission (550)'
                            % (locate_return)
                        )
                    else:
                        check_results['medium'].append(\
                            'The file %s is using harmful permission (550)'
                            % (locate_return)
                        )
        else:
            check_results['info'].append(
                'Could not find a .htpasswd file. Please, run updatedb'
            )
        # If there is, closing the apache_config file
        if not apache_conf_file_found:
            check_results['info'].append(
                'Could not find Apache\'s configuration files'
            )

        return check_results