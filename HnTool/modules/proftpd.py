# -*- coding: utf-8 -*-
#
# HnTool rules - protftpd
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import os
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule

class Rule(MasterRule):
	def __init__(self, options):
		MasterRule.__init__(self, options)
		self.short_name="proftpd"
		self.long_name="Checks security problems on ProFTPd servers"
		self.type="config"

	def analyze(self, options):
		check_results = self.check_results
		proftpd_conf_file = ['/etc/proftpd.conf']
		proftpd_conf_file_found = False

		for proftpd_conf in proftpd_conf_file:
			if os.path.isfile(proftpd_conf):
				# dict with all the lines
				lines = HnTool.modules.util.hntool_conf_parser(proftpd_conf)
				proftpd_conf_file_found = True

				# Checking if ProFTPd is using the default port
				if 'Port' in lines:
					if int(lines['Port']) == 21:
						check_results['info'].append('ProFTPd is running under default port (21)')
					elif int(lines['Port']) != 21:
						check_results['info'].append('ProFTPd is running under port ' +
							                                 lines['Port'])
				else: # if we didn't found 'Ports' in lines than ProFTPd uses the default one
					check_results['info'].append('ProFTPd is running under default port (21)')

				# Checking if ProFTPd allows more than 3 login attempts
				if 'MaxLoginAttempts' in lines:
					if int(lines['MaxLoginAttempts']) > 3:
						check_results['medium'].append('ProFTPd allows more than 3 login attempts')
					elif int(lines['MaxLoginAttempts']) <= 3:
						check_results['ok'].append('ProFTPd does not allows more than 3 login attempts')
				else:
					# if we didn't found 'MaxLoginAttempts' in lines than ProFTPd uses the
					# default value for this, which is 3
					check_results['medium'].append('ProFTPd allows more than 3 login attempts')

				# Checking if ProFTPd allows root login
				if 'RootLogin' in lines:
					if lines['RootLogin'] == 'on':
						check_results['medium'].append('ProFTPd allows root login')
					elif lines['RootLogin'] == 'off':
						check_results['ok'].append('ProFTPd does not allows root login')
				else:
					# if we didn't found 'RootLogin' in lines than ProFTPd uses the
					# default value for this. By default proftpd disallows root logins
					check_results['ok'].append('ProFTPd does not allows root login')

				# Checking if ProFTPd allows footprinting
				if 'ServerIdent' in lines:
					if lines['ServerIdent'] == 'on':
						check_results['medium'].append('ProFTPd allows footprinting')
					elif lines['ServerIdent'] == 'off':
						check_results['ok'].append('ProFTPd does not allows footprinting')
				else:
					check_results['ok'].append('ProFTPd allows footprinting')

				# Checking if we chroot users into the ftp users' home directory
				if 'DefaultRoot' in lines:
					if lines['DefaultRoot'] != '~':
						check_results['medium'].append('ProFTPd does not chroot users')
					elif lines['DefaultRoot'] != '~':
						check_results['ok'].append('ProFTPd chroot users')
				else:
					check_results['medium'].append('ProFTPd does not chroot users')

		if not proftpd_conf_file_found:
			check_results['info'].append('Could not find a proftpd.conf file')

		return check_results