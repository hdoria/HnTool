# -*- coding: utf-8 -*-
#
# HnTool rules - authentication
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
import stat
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule

class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name="authentication"
        self.long_name="Checks users, groups and authentications"
        self.type="config"

    def analyze(self, options):
        check_results = self.check_results
        passwd_file = '/etc/passwd'
        shadow_file = '/etc/shadow'
        logindefs_file = '/etc/login.defs'
        invalid_shell = ['/sbin/nologin', '/bin/false', '/usr/bin/false', \
                         '/var/empty/usr/bin/false', '/usr/sbin/nologin']

        # Checks about the shadow file
        if os.path.isfile(shadow_file):
            # Checking passwd_file permissions
            if oct(os.stat(shadow_file)[stat.ST_MODE] & 0777) == oct(0400):
                check_results['ok'].append('Permissions on shadow file are '+
                                           'correct (400)')
            if oct(os.stat(shadow_file)[stat.ST_MODE] & 0777) == oct(0600):
                check_results['ok'].append('Permissions on shadow file are '+
                                           'correct (600)')
            elif oct(os.stat(shadow_file)[stat.ST_MODE] & 0777) > oct(0600):
                check_results['high'].append('Permissions on shadow file are '+
                                             'greater than 600')

        # Checks about the passwd file
        if os.path.isfile(passwd_file):
            # Checking passwd_file permissions
            if oct(os.stat(passwd_file)[stat.ST_MODE] & 0777) == oct(0644):
                check_results['ok'].append('Permissions on passwd file are '+
                                           'correct (644)')
            elif oct(os.stat(passwd_file)[stat.ST_MODE] & 0777) > oct(0644):
                check_results['high'].append('Permissions on passwd file are '+
                                             'greater than 644')

            # Gets the values of each line of the passwd file
            passwd_fp = open(passwd_file, 'r')
            users = [x.strip('\n').split(':') for x in passwd_fp.readlines()]

            users = [x for i, x in enumerate(users) \
                     if not (x[0].startswith('#') or not (x[0] != ''))]
            for indexc, line in enumerate(users):
                for indexv, col in enumerate(line):
                    users[indexc][indexv] = col.strip()

            if users:

                # will be true if we find users with UID 0
                users_with_uid_zero = False

                # Checking if there's a user (other than root) that has UID 0
                for user in users:
                    if user[0] != 'root' and user[2] == '0':
                        check_results['high'].append('There is a user (not root) ' +
                                                     'with UID 0')
                        users_with_uid_zero = True

                    # Checking if there's a user (other than root)
                    # with a valid shell
                    if user[0] != 'root' and user[-1] not in invalid_shell:
                        check_results['medium'].append('User "' + user[0] + '" may ' +
                                                       'have a harmful shell (' + user[-1] + ')')

                if not users_with_uid_zero:
                    check_results['ok'].append("There aren't users (not root) " +
                                               " with UID 0")

            # closing the passwd file
            passwd_fp.close()

        # Checking permissions on home directories (including /root)
        home_permissions_problems = False
        for dir in os.listdir('/home'):
            if os.path.isdir('/home/' + dir):
                if oct(os.stat('/home/' + dir)[stat.ST_MODE] & 0777) > oct(0100):
                    check_results['medium'].append('Permissions on /home/' + dir +
                                                   ' are greater than 700')
                    home_permissions_problems = True

        # Checking the permissions of the root home directory
        if os.path.exists('/root'):
            if oct(os.stat('/root')[stat.ST_MODE] & 0777) > oct(0750):
                check_results['medium'].append('Permissions on /root dir are '+
                                               'greater than 700')
                home_permissions_problems = True

        if not home_permissions_problems:
            # if we got here, then we didnt found permissions problems
            check_results['ok'].append('Did not found permissions ' +
                                       'problems on home directories')

        # Checks about the login.defs file
        if os.path.isfile(logindefs_file):
            lines = HnTool.modules.util.hntool_conf_parser(logindefs_file)

            # Checking when passwords expires
            if 'PASS_MAX_DAYS' in lines:
                if int(lines['PASS_MAX_DAYS']) > 90:
                    check_results['medium'].append('By default passwords do not ' +
                                                   'expires on 90 days or less')
                else:
                    check_results['ok'].append('By default passwords expires ' +
                                               'on 90 days or less')
            else:
                check_results['high'].append('By default passwords does not expires')

            # Checking the fail delay
            if 'FAIL_DELAY' in lines:
                if int(lines['FAIL_DELAY']) < 3:
                    check_results['medium'].append('Delay between failed login prompts is less than 3s')
                else:
                    check_results['ok'].append('Delay between failed login prompts is more than 3s')
            else:
                check_results['high'].append('Delay between failed login prompts is not defined')

            # Checking pass min days
            if 'PASS_MIN_DAYS' in lines:
                if int(lines['PASS_MIN_DAYS']) < 5:
                    check_results['medium'].append('Min. number of days between password changes is less than 5')
                else:
                    check_results['ok'].append('Min. number of days between password changes is more than 5')
            else:
                check_results['high'].append('Min. number of days between password changes is not defined')

        return check_results