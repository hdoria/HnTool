# -*- coding: utf-8 -*-
#
# HnTool rules - vsftpd
# Copyright (C) 2010 Hugo Doria <mail@hugodoria.org>
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
        self.short_name="vsftpd"
        self.long_name="Checks security problems on VsFTPd servers"
        self.type="config"
        self.required_files = ['/etc/vsftpd.conf', '/etc/vsftpd/vsftpd.conf']

    def requires(self):
        return self.required_files

    def vsftpdParser(self, pfile):
        '''Method to parse a vsftpd.conf file. Returns a dict with
        all [key, value] of the file.'''

        if os.path.isfile(pfile):
            fp = open(pfile,'r')

            keysValues = {}
            for line in fp.readlines():
                if not line.startswith('#'):
                    line = line.strip().split('=')

                    if len(line) >= 2:
                        keysValues[line[0]] = line[1]

            fp.close()

            return keysValues

    def analyze(self, options):
        check_results = self.check_results
        vsftpd_conf_file = self.required_files

        # getting the lines in a [key. value] format
        for vsftpd_conf in vsftpd_conf_file:
            if os.path.isfile(vsftpd_conf):
                lines = self.vsftpdParser(vsftpd_conf)

        # checking if VsFTPd is running on Standalone method
        if 'listen' in lines:
            if lines['listen'].upper() == 'YES':
                check_results['info'].append('Running on StandAlone')
            else:
                check_results['info'].append('Not running on StandAlone')
        else:
            check_results['info'].append('Running on StandAlone')

        # checking if VsFTPd is using the default port
        if 'listen_port' in lines:
            if int(lines['listen_port']) == 21:
                check_results['info'].append('Using the default port (21)')
            else:
                check_results['info'].append('Not using the default port (21)')
        else:
            check_results['info'].append('Using the default port (21)')

        # checking if chroot is enabled on VsFTPd
        if 'chroot_local_user' in lines:
            if lines['chroot_local_user'].upper() == 'YES':
                check_results['ok'].append('Chrooting local users is enabled')
            else:
                check_results['high'].append('Chrooting local users is disabled')
        else:
            check_results['high'].append('Chrooting local users is disabled')

        # checking if anonymous login is enabled
        if 'anonymous_enable' in lines:
            if lines['anonymous_enable'].upper() == 'YES':
                check_results['info'].append('Anonymous login is allowed')
            else:
                check_results['info'].append('Anonymous login is not allowed')
        else:
            check_results['info'].append('Anonymous login is allowed')

        # checking if ascii_download_enable or ascii_upload_enable is enabled
        if 'ascii_download_enable' in lines or 'ascii_upload_enable' in lines:
            if lines['ascii_download_enable'].upper() == 'YES' or \
            lines['ascii_upload_enable'].upper() == 'YES':
                check_results['high'].append('ASCII mode data transfers is allowed (DoS is possible)')
            else:
                check_results['ok'].append('ASCII mode data transfers is not allowed')
        else:
            check_results['high'].append('ASCII mode data transfers is allowed (DoS is possible)')

        return check_results