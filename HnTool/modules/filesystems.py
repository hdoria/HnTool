# -*- coding: utf-8 -*-
#
# HnTool rules - filesystems
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
import commands
from HnTool.modules.rule import Rule as MasterRule

class Rule(MasterRule):
	def __init__(self, options):
		MasterRule.__init__(self, options)
		self.short_name="filesystems"
		self.long_name="Checks filesystems for security problems"
		self.type="config"

	def analyze(self, options):
		check_results = self.check_results
		locate_database = {'nix': '/var/lib/mlocate/mlocate.db', \
						   'bsd': '/var/db/locate.database'}
		updatedb_command = {'nix': '/usr/bin/updatedb', \
						    'bsd': '/usr/libexec/locate.updatedb'}

		# Checking if the locate database exists
		if not os.path.isfile(locate_database['nix']) and \
		not os.path.isfile(locate_database['bsd']):
			if os.path.isfile(updatedb_command['nix']):
				check_results['info'].append('%s not found. Please run %s' % \
				(locate_database['nix'], updatedb_command['nix']))
				os_type = 'nix'
			elif os.path.isfile(updatedb_command['bsd']):
				check_results['info'].append('%s not found. Please run %s' % \
				(locate_database['bsd'], updatedb_command['bsd']))
				os_type = 'bsd'
		elif os.path.isfile(locate_database['bsd']):
			check_results['ok'].append('locate.database found.')
			os_type = 'bsd'
		elif os.path.isfile(locate_database['nix']):
			check_results['ok'].append('mlocate.db found.')
			os_type = 'nix'
		# Checking for old files
		datafile = locate_database[os_type]
		files_old = ['/tmp', datafile]

		for files in files_old:
			find_status, find_results = \
			commands.getstatusoutput('find %s -type f -atime +30' % files)
			if find_status != 0:
				check_results['low'].append('Found old file(s) (+30 days) in ' + files)
				if files == datafile:
					check_results['info'].append('Please run %s' % updatedb_command[os_type])
			else:
				check_results['ok'].append('Did not found old file(s) (+30 days) in ' + files)

		return check_results